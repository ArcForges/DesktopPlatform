// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.IO.Pipes;
using System.Net.Sockets;

namespace ArcForges.LocalRpc;

/// <summary>Produces connected duplex OS streams for one listener until it is unbound.</summary>
internal interface IStreamAcceptSource : IAsyncDisposable
{
    /// <summary>Waits for the next stream; null means the source is unbound or completed.</summary>
    ValueTask<Stream?> AcceptAsync(CancellationToken cancellationToken);

    /// <summary>Stops accepting and releases the endpoint name so a new client cannot connect.</summary>
    ValueTask UnbindAsync();
}

/// <summary>A Windows Named Pipe listener whose every instance is limited to the current user.</summary>
internal sealed class NamedPipeAcceptSource : IStreamAcceptSource
{
    private readonly string _name;
    private readonly bool _service;
    private readonly CancellationTokenSource _stop = new();
    private readonly object _gate = new();
    private NamedPipeServerStream? _pending;
    private bool _unbound;

    private NamedPipeAcceptSource(string name, bool service)
    {
        _name = name;
        _service = service;
    }

    /// <summary>
    /// Creates the first instance with FirstPipeInstance, so binding fails if any instance of the name already exists
    /// (the runtime sets FILE_FLAG_FIRST_PIPE_INSTANCE only through this option). Later instances of this listener
    /// join the name it owns.
    /// </summary>
    internal static NamedPipeAcceptSource Bind(string name)
    {
        var source = new NamedPipeAcceptSource(name, service: false);
        source._pending = source.CreateInstance(first: true);
        return source;
    }

    /// <summary>
    /// Binds a service-mode pipe: every instance carries the explicit same-user access list (owner the current user, the current user
    /// and SYSTEM allowed, NETWORK denied) and <c>PIPE_REJECT_REMOTE_CLIENTS</c>; the first instance uses <c>FILE_FLAG_FIRST_PIPE_INSTANCE</c>.
    /// </summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    internal static NamedPipeAcceptSource BindService(string name)
    {
        var source = new NamedPipeAcceptSource(name, service: true);
        source._pending = source.CreateInstance(first: true);
        return source;
    }

    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the accepted pipe passes to the caller; every other path disposes it.")]
    public async ValueTask<Stream?> AcceptAsync(CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _stop.Token);
        while (!linked.IsCancellationRequested)
        {
            var pipe = TakePending();
            if (pipe is null)
            {
                return null;
            }

            try
            {
                await pipe.WaitForConnectionAsync(linked.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
                return null;
            }
            catch (IOException)
            {
                // A client connected and disappeared before the stream was handed over: wait for the next one.
                await pipe.DisposeAsync().ConfigureAwait(false);
                continue;
            }

            return pipe;
        }

        return null;
    }

    public async ValueTask UnbindAsync()
    {
        NamedPipeServerStream? pending;
        lock (_gate)
        {
            _unbound = true;
            pending = _pending;
            _pending = null;
        }

        await _stop.CancelAsync().ConfigureAwait(false);
        if (pending is not null)
        {
            await pending.DisposeAsync().ConfigureAwait(false);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await UnbindAsync().ConfigureAwait(false);
        _stop.Dispose();
    }

    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the taken instance passes to the caller and the spare instance is owned by this source until it is taken or unbound.")]
    private NamedPipeServerStream? TakePending()
    {
        lock (_gate)
        {
            if (_unbound)
            {
                return null;
            }

            var pipe = _pending ?? CreateInstance(first: false);
            try
            {
                _pending = CreateInstance(first: false);
            }
            catch (IOException)
            {
                // The spare instance is recreated by the next accept; this connection is still served.
                _pending = null;
            }

            return pipe;
        }
    }

    private NamedPipeServerStream CreateInstance(bool first) => _service && OperatingSystem.IsWindows()
        ? LocalRpcWindowsNative.CreateServicePipe(_name, first)
        : CreatePlainInstance(first);

    private NamedPipeServerStream CreatePlainInstance(bool first) => new(
        _name,
        PipeDirection.InOut,
        NamedPipeServerStream.MaxAllowedServerInstances,
        PipeTransmissionMode.Byte,
        PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly | (first ? PipeOptions.FirstPipeInstance : PipeOptions.None));
}

/// <summary>
/// A Unix domain socket listener that binds only inside an owner-only directory, never replaces an existing
/// file and keeps the socket file itself owner-only.
/// </summary>
internal sealed class UnixSocketAcceptSource : IStreamAcceptSource
{
    private const UnixFileMode GroupAndOther = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
        | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

    private readonly Socket _listener;
    private readonly string _path;
    private readonly CancellationTokenSource _stop = new();
    private int _unbound;

    private UnixSocketAcceptSource(Socket listener, string path)
    {
        _listener = listener;
        _path = path;
    }

    internal static UnixSocketAcceptSource Bind(string path, int backlog)
    {
        RequireOwnerOnlyDirectory(path);
        if (File.Exists(path) || Directory.Exists(path))
        {
            throw new IOException("The Unix socket endpoint already exists; it is never replaced or reused.");
        }

        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        var created = false;
        try
        {
            socket.Bind(new UnixDomainSocketEndPoint(path));
            created = true;
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            socket.Listen(backlog);
            return new UnixSocketAcceptSource(socket, path);
        }
        catch
        {
            socket.Dispose();
            if (created)
            {
                DeleteQuietly(path);
            }

            throw;
        }
    }

    /// <summary>
    /// Binds a service-mode socket at a well-known path (Design 02 §2.7): the directory is created owner-only (0700) when it is missing and
    /// must be an owner-only directory, not a link, when it exists. An entry left at the path that accepts no connection (the socket of a
    /// server that is gone) is removed first: the directory is owner-only, so only this user can have put it there. A live server's socket,
    /// a link or a directory at the path is never touched and binding fails.
    /// </summary>
    internal static UnixSocketAcceptSource BindService(string path, int backlog)
    {
        var directory = Path.GetDirectoryName(path);
        if (string.IsNullOrEmpty(directory))
        {
            throw new DirectoryNotFoundException("The Unix socket directory must be named.");
        }

        if (!Directory.Exists(directory))
        {
            var parent = Path.GetDirectoryName(directory);
            if (string.IsNullOrEmpty(parent) || !Directory.Exists(parent))
            {
                throw new DirectoryNotFoundException("The parent of the service socket directory must already exist.");
            }

            if (OperatingSystem.IsWindows())
            {
                _ = Directory.CreateDirectory(directory);
            }
            else
            {
                _ = Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
        }

        if (new DirectoryInfo(directory).LinkTarget is not null)
        {
            throw new UnauthorizedAccessException("The service socket directory is never a link.");
        }

        RequireOwnerOnlyDirectory(path);
        RemoveStaleServiceSocket(path);
        return Bind(path, backlog);
    }

    /// <summary>Removes a socket that no server accepts on; refuses anything else at a service socket path.</summary>
    private static void RemoveStaleServiceSocket(string path)
    {
        var entry = new FileInfo(path);
        if (Directory.Exists(path) || (entry.Exists && entry.LinkTarget is not null))
        {
            throw new IOException("The service socket path names a directory or a link; it is never replaced.");
        }

        if (!entry.Exists)
        {
            return;
        }

        using (var probe = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified))
        {
            try
            {
                probe.Connect(new UnixDomainSocketEndPoint(path));
                throw new IOException("A server already listens on the service socket; a service endpoint is never shared or replaced.");
            }
            catch (SocketException exception) when (exception.SocketErrorCode is SocketError.ConnectionRefused or SocketError.AddressNotAvailable)
            {
                // Nothing accepts on it: the socket of a server that is gone.
            }
        }

        File.Delete(path);
    }

    /// <summary>Refuses a socket directory that any other user could list, write or traverse (mode must be 0700-or-stricter).</summary>
    internal static void RequireOwnerOnlyDirectory(string socketPath)
    {
        var directory = Path.GetDirectoryName(socketPath);
        if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory))
        {
            throw new DirectoryNotFoundException("The Unix socket directory must already exist.");
        }

        if (!OperatingSystem.IsWindows() && (File.GetUnixFileMode(directory) & GroupAndOther) != 0)
        {
            throw new UnauthorizedAccessException("The Unix socket directory must be accessible by its owner only.");
        }
    }

    public async ValueTask<Stream?> AcceptAsync(CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _stop.Token);
        while (!linked.IsCancellationRequested)
        {
            try
            {
                var socket = await _listener.AcceptAsync(linked.Token).ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (OperationCanceledException)
            {
                return null;
            }
            catch (ObjectDisposedException)
            {
                return null;
            }
            catch (SocketException exception) when (Volatile.Read(ref _unbound) != 0
                || exception.SocketErrorCode is SocketError.OperationAborted or SocketError.Interrupted or SocketError.Shutdown)
            {
                return null;
            }
            catch (SocketException)
            {
                // A connection reset before accept completed: wait for the next client.
            }
        }

        return null;
    }

    public async ValueTask UnbindAsync()
    {
        if (Interlocked.Exchange(ref _unbound, 1) == 0)
        {
            await _stop.CancelAsync().ConfigureAwait(false);
            _listener.Dispose();
            DeleteQuietly(_path);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await UnbindAsync().ConfigureAwait(false);
        _stop.Dispose();
    }

    private static void DeleteQuietly(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
            // Best-effort removal of the endpoint this listener created.
        }
        catch (UnauthorizedAccessException)
        {
            // Best-effort removal of the endpoint this listener created.
        }
    }
}

/// <summary>Accepts only the streams a launcher supplied.</summary>
internal sealed class SuppliedStreamAcceptSource(LocalRpcStreamSupplier supplier) : IStreamAcceptSource
{
    private readonly CancellationTokenSource _stop = new();

    public async ValueTask<Stream?> AcceptAsync(CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _stop.Token);
        try
        {
            return await supplier.AcceptAsync(linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return null;
        }
    }

    public async ValueTask UnbindAsync()
    {
        await _stop.CancelAsync().ConfigureAwait(false);
        await supplier.DisposeUnacceptedAsync().ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        await UnbindAsync().ConfigureAwait(false);
        _stop.Dispose();
    }
}
