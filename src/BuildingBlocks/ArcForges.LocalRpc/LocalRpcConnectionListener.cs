// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Connections;

namespace ArcForges.LocalRpc;

/// <summary>Describes one accepted connection to the authorization decision, before any byte is read from it.</summary>
public sealed record LocalRpcConnectionInfo(LocalRpcTransport Transport, long Sequence, LocalRpcEndpoint? Endpoint = null)
{
    /// <summary>
    /// The operating-system identity of the peer process: always set by a service-mode server (a peer that could not be resolved, that
    /// exited or that runs as another user never reaches the decision), and always null for a parent-child server, which reads no peer.
    /// </summary>
    public LocalRpcPeer? Peer { get; init; }
}

/// <summary>The Kestrel endpoint that selects this transport. It carries the owner's listener recipe.</summary>
internal sealed class LocalRpcListenEndPoint : EndPoint
{
    internal LocalRpcListenEndPoint(
        LocalRpcEndpoint? endpoint,
        LocalRpcStreamSupplier? supplier,
        LocalRpcLimits limits,
        Func<LocalRpcConnectionInfo, CancellationToken, ValueTask<bool>>? authorizer,
        LocalRpcBoundsRegistry bounds,
        LocalRpcPeerResolver? peerResolver = null)
    {
        Endpoint = endpoint;
        Supplier = supplier;
        Limits = limits;
        Authorizer = authorizer;
        Bounds = bounds;
        PeerResolver = peerResolver;
    }

    /// <summary>Set exactly for a service-mode server: every accepted stream's peer is resolved before HTTP/2 reads a byte.</summary>
    internal LocalRpcPeerResolver? PeerResolver { get; }

    internal LocalRpcEndpoint? Endpoint { get; }

    internal LocalRpcStreamSupplier? Supplier { get; }

    internal LocalRpcLimits Limits { get; }

    internal Func<LocalRpcConnectionInfo, CancellationToken, ValueTask<bool>>? Authorizer { get; }

    internal LocalRpcBoundsRegistry Bounds { get; }

    internal LocalRpcTransport Transport => Endpoint?.Transport ?? (OperatingSystem.IsWindows()
        ? LocalRpcTransport.NamedPipe : LocalRpcTransport.UnixDomainSocket);

    public override AddressFamily AddressFamily => AddressFamily.Unspecified;

    public override string ToString() => Endpoint is null
        ? "localrpc:supplied-streams"
        : $"localrpc:{Endpoint.Transport}:{Endpoint.Address}";
}

/// <summary>
/// The only <see cref="IConnectionListenerFactory"/> a server registers: it can bind nothing but
/// <see cref="LocalRpcListenEndPoint"/>, so an IP, loopback or port endpoint cannot be listened on.
/// </summary>
internal sealed class LocalRpcConnectionListenerFactory : IConnectionListenerFactory, IConnectionListenerFactorySelector
{
    public bool CanBind(EndPoint endpoint) => endpoint is LocalRpcListenEndPoint;

    [SuppressMessage("Reliability", "CA2000", Justification = "The listener owns the accept source and Kestrel disposes the listener.")]
    public ValueTask<IConnectionListener> BindAsync(EndPoint endpoint, CancellationToken cancellationToken = default)
    {
        if (endpoint is not LocalRpcListenEndPoint local)
        {
            throw new NotSupportedException("Only private local RPC endpoints can be bound.");
        }

        IStreamAcceptSource source;
        if (local.Supplier is { } supplier)
        {
            source = new SuppliedStreamAcceptSource(supplier);
        }
        else if (local.Endpoint is { Transport: LocalRpcTransport.NamedPipe } pipe)
        {
            source = local.PeerResolver is not null && OperatingSystem.IsWindows()
                ? NamedPipeAcceptSource.BindService(pipe.Address)
                : NamedPipeAcceptSource.Bind(pipe.Address);
        }
        else if (local.Endpoint is { Transport: LocalRpcTransport.UnixDomainSocket } socket)
        {
            source = local.PeerResolver is not null
                ? UnixSocketAcceptSource.BindService(socket.Address, LocalRpcConnectionListener.Backlog)
                : UnixSocketAcceptSource.Bind(socket.Address, LocalRpcConnectionListener.Backlog);
        }
        else
        {
            throw new NotSupportedException("A local RPC endpoint names exactly one private stream transport.");
        }

        return ValueTask.FromResult<IConnectionListener>(new LocalRpcConnectionListener(local, source));
    }
}

/// <summary>
/// Accepts connected streams, applies the connection authorizer and hands HTTP/2 only authorized ones. At most
/// <see cref="LocalRpcLimits.MaxConnections"/> connections are served at once: the listener waits for a free slot
/// before it accepts, so an extra peer waits in the OS backlog instead of being reset, and a slot is freed only when
/// the previous connection has been fully torn down.
/// </summary>
internal sealed class LocalRpcConnectionListener : IConnectionListener
{
    /// <summary>Pending OS connections allowed to wait for a slot; independent of the connection bound.</summary>
    internal const int Backlog = 16;

    private readonly LocalRpcListenEndPoint _endPoint;
    private readonly IStreamAcceptSource _source;
    private readonly SemaphoreSlim _slots;
    private readonly CancellationTokenSource _stop = new();
    private long _sequence;

    internal LocalRpcConnectionListener(LocalRpcListenEndPoint endPoint, IStreamAcceptSource source)
    {
        _endPoint = endPoint;
        _source = source;
        _slots = new SemaphoreSlim(endPoint.Limits.MaxConnections, endPoint.Limits.MaxConnections);
    }

    public EndPoint EndPoint => _endPoint;

    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the connection context passes to Kestrel, which disposes it; a denied stream is disposed here.")]
    public async ValueTask<ConnectionContext?> AcceptAsync(CancellationToken cancellationToken = default)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _stop.Token);
        try
        {
            while (true)
            {
                await _slots.WaitAsync(linked.Token).ConfigureAwait(false);
                var handedOver = false;
                try
                {
                    var stream = await _source.AcceptAsync(linked.Token).ConfigureAwait(false);
                    if (stream is null)
                    {
                        return null;
                    }

                    var accepted = _endPoint.PeerResolver is null ? default : LocalRpcAcceptMoment.Now();
                    var sequence = Interlocked.Increment(ref _sequence);
                    var info = new LocalRpcConnectionInfo(_endPoint.Transport, sequence, _endPoint.Endpoint);
                    bool allowed;
                    LocalRpcPeer? peerIdentity = null;
                    try
                    {
                        if (_endPoint.PeerResolver is { } resolver)
                        {
                            peerIdentity = await DecideServiceAsync(resolver, info, stream, accepted, linked.Token).ConfigureAwait(false);
                            allowed = peerIdentity is not null;
                        }
                        else
                        {
                            allowed = await AuthorizeAsync(info, linked.Token).ConfigureAwait(false);
                        }
                    }
                    catch
                    {
                        // The server is stopping: the accepted stream is dropped unread.
                        await stream.DisposeAsync().ConfigureAwait(false);
                        throw;
                    }

                    if (!allowed)
                    {
                        // Fail closed: an unauthorized peer receives no byte and its stream is dropped without being read.
                        await stream.DisposeAsync().ConfigureAwait(false);
                        continue;
                    }

                    // The peer's call bounds and watchdog live exactly as long as its connection: the slot is released
                    // and the bounds dropped only when the connection has been fully torn down.
                    var connectionId = $"localrpc-{sequence}";
                    var peer = _endPoint.Bounds.Add(connectionId, peerIdentity);
                    var context = new StreamConnectionContext(connectionId, stream, _endPoint, () =>
                    {
                        _endPoint.Bounds.Remove(peer);
                        ReleaseSlot();
                    });
                    if (peer.Identity is { } identityFeature)
                    {
                        context.Features.Set(identityFeature);
                    }

                    handedOver = true;
                    peer.Start(context.Abort);
                    return context;
                }
                finally
                {
                    if (!handedOver)
                    {
                        ReleaseSlot();
                    }
                }
            }
        }
        catch (Exception exception) when (exception is OperationCanceledException or ObjectDisposedException)
        {
            return null;
        }
    }

    public async ValueTask UnbindAsync(CancellationToken cancellationToken = default)
    {
        await _stop.CancelAsync().ConfigureAwait(false);
        await _source.UnbindAsync().ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        await UnbindAsync().ConfigureAwait(false);
        await _source.DisposeAsync().ConfigureAwait(false);
        _stop.Dispose();
        _slots.Dispose();
    }

    private void ReleaseSlot()
    {
        try
        {
            _ = _slots.Release();
        }
        catch (ObjectDisposedException)
        {
            // The listener was disposed while a connection was still tearing down.
        }
        catch (SemaphoreFullException)
        {
            // Never raised by a once-only release; kept so a teardown race cannot fault Kestrel.
        }
    }

    /// <summary>
    /// The service-mode decision for one connection: the peer is resolved from the OS stream (never read), a peer that is unresolved, gone or
    /// of another user is dropped, and the owner's decision then sees the peer. The whole decision is bounded by
    /// <see cref="LocalRpcLimits.AuthorizationTimeout"/>; the accept loop awaits it, so accepts are serial, as on the parent-child path. Returns
    /// the admitted peer, or null.
    /// </summary>
    [SuppressMessage("Design", "CA1031", Justification = "A failing resolution or decision must deny rather than expose an unauthenticated connection.")]
    private async ValueTask<LocalRpcPeer?> DecideServiceAsync(
        LocalRpcPeerResolver resolver,
        LocalRpcConnectionInfo connection,
        Stream stream,
        LocalRpcAcceptMoment accepted,
        CancellationToken cancellationToken)
    {
        var authorizer = _endPoint.Authorizer;
        using var decision = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        decision.CancelAfter(_endPoint.Limits.AuthorizationTimeout);

        // What a failure or a timeout is counted as: an unresolved peer until the OS has named it, the owner's refusal after that.
        var stage = (int)LocalRpcPeerDenial.Unresolved;
        LocalRpcPeerDenial? denial = null;
        try
        {
            var pending = Task.Run(
                async () =>
                {
                    var resolution = resolver.Resolve(stream, accepted);
                    if (resolution.Peer is not { } peer)
                    {
                        return new ServiceDecision(resolution.Denial == LocalRpcPeerDenial.None ? LocalRpcPeerDenial.Unresolved : resolution.Denial, null);
                    }

                    Volatile.Write(ref stage, (int)LocalRpcPeerDenial.Refused);
                    return authorizer is null || await authorizer(connection with { Peer = peer }, decision.Token).ConfigureAwait(false)
                        ? new ServiceDecision(LocalRpcPeerDenial.None, peer)
                        : new ServiceDecision(LocalRpcPeerDenial.Refused, null);
                },
                CancellationToken.None);
            _ = pending.ContinueWith(
                static task => _ = task.Exception,
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
            var outcome = await pending.WaitAsync(_endPoint.Limits.AuthorizationTimeout, cancellationToken).ConfigureAwait(false);
            denial = outcome.Denial;
            return outcome.Peer;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The server is stopping: nothing is decided or counted.
            throw;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            denial = (LocalRpcPeerDenial)Volatile.Read(ref stage);
            return null;
        }
        finally
        {
            if (denial is { } counted)
            {
                _endPoint.Bounds.CountPeerDecision(counted);
            }

            await decision.CancelAsync().ConfigureAwait(false);
        }
    }

    private readonly record struct ServiceDecision(LocalRpcPeerDenial Denial, LocalRpcPeer? Peer);

    /// <summary>
    /// Asks the decision for one connection. A decision that throws, ignores its token past
    /// <see cref="LocalRpcLimits.AuthorizationTimeout"/> or is cancelled by anything but the server stopping denies the connection.
    /// </summary>
    [SuppressMessage("Design", "CA1031", Justification = "A throwing authorizer must deny rather than expose an unauthenticated connection.")]
    private async ValueTask<bool> AuthorizeAsync(LocalRpcConnectionInfo connection, CancellationToken cancellationToken)
    {
        if (_endPoint.Authorizer is not { } authorizer)
        {
            return true;
        }

        using var decision = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        decision.CancelAfter(_endPoint.Limits.AuthorizationTimeout);
        try
        {
            // Off the accept loop: a decision that blocks its thread instead of yielding is still bounded by the timeout.
            var pending = Task.Run(async () => await authorizer(connection, decision.Token).ConfigureAwait(false), CancellationToken.None);
            _ = pending.ContinueWith(
                static task => _ = task.Exception,
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
            return await pending.WaitAsync(_endPoint.Limits.AuthorizationTimeout, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            return false;
        }
        finally
        {
            // Whatever ended the wait (a timeout included), a decision still running is told to stop.
            await decision.CancelAsync().ConfigureAwait(false);
        }
    }
}
