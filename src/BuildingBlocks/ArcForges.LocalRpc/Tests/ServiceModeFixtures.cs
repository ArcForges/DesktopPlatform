// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using Grpc.Core;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// A hand-written, test-only service shaped like generated code for the service-mode tests (AF-DP-01). The pinned contracts have no
/// server-streaming method and no node service, and the library is contract-agnostic, so this probe stands in for a node's data methods
/// (Work, Wait), its peer-aware method (WhoAmI) and its long-lived subscriptions (Subscribe in the stream lane; Feed, a streaming method
/// left as a data call). It proves library behaviour only, never the contract of a real service.
/// </summary>
internal static class ServiceProbe
{
    internal const string ServiceName = "arcforges.test.service.v1.ServiceProbe";

    private static readonly Marshaller<byte[]> Bytes = Marshallers.Create(value => value, value => value);

    internal static readonly Method<byte[], byte[]> Work = new(MethodType.Unary, ServiceName, "Work", Bytes, Bytes);

    internal static readonly Method<byte[], byte[]> Wait = new(MethodType.Unary, ServiceName, "Wait", Bytes, Bytes);

    internal static readonly Method<byte[], byte[]> WhoAmI = new(MethodType.Unary, ServiceName, "WhoAmI", Bytes, Bytes);

    internal static readonly Method<byte[], byte[]> Subscribe = new(MethodType.ServerStreaming, ServiceName, "Subscribe", Bytes, Bytes);

    internal static readonly Method<byte[], byte[]> Feed = new(MethodType.ServerStreaming, ServiceName, "Feed", Bytes, Bytes);

    public static void BindService(ServiceBinderBase binder, ServiceProbeBase? service)
    {
        ArgumentNullException.ThrowIfNull(binder);
        binder.AddMethod(Work, service is null ? null : new UnaryServerMethod<byte[], byte[]>(service.Work));
        binder.AddMethod(Wait, service is null ? null : new UnaryServerMethod<byte[], byte[]>(service.Wait));
        binder.AddMethod(WhoAmI, service is null ? null : new UnaryServerMethod<byte[], byte[]>(service.WhoAmI));
        binder.AddMethod(Subscribe, service is null ? null : new ServerStreamingServerMethod<byte[], byte[]>(service.Subscribe));
        binder.AddMethod(Feed, service is null ? null : new ServerStreamingServerMethod<byte[], byte[]>(service.Feed));
    }

    [BindServiceMethod(typeof(ServiceProbe), nameof(BindService))]
    internal abstract class ServiceProbeBase
    {
        public virtual Task<byte[]> Work(byte[] request, ServerCallContext context) => throw new RpcException(new Status(StatusCode.Unimplemented, string.Empty));

        public virtual Task<byte[]> Wait(byte[] request, ServerCallContext context) => throw new RpcException(new Status(StatusCode.Unimplemented, string.Empty));

        public virtual Task<byte[]> WhoAmI(byte[] request, ServerCallContext context) => throw new RpcException(new Status(StatusCode.Unimplemented, string.Empty));

        public virtual Task Subscribe(byte[] request, IServerStreamWriter<byte[]> responseStream, ServerCallContext context) => throw new RpcException(new Status(StatusCode.Unimplemented, string.Empty));

        public virtual Task Feed(byte[] request, IServerStreamWriter<byte[]> responseStream, ServerCallContext context) => throw new RpcException(new Status(StatusCode.Unimplemented, string.Empty));
    }
}

/// <summary>What a Subscribe call does.</summary>
internal enum SubscribeMode : byte
{
    /// <summary>The owner's heartbeat: one small message every interval until the stream ends.</summary>
    Heartbeat = 1,

    /// <summary>Up to the given count of messages of the given size, the given interval apart (none: as fast as the writer takes them).</summary>
    Burst = 2,

    /// <summary>Opens the stream and writes nothing until it ends.</summary>
    Silent = 3,
}

/// <summary>The probe's behaviour; it records what each call saw so a test can check the library's decisions from the handler's side.</summary>
internal sealed class ServiceProbeService : ServiceProbe.ServiceProbeBase
{
    private readonly ConcurrentDictionary<int, TimeSpan> _remainingAtStart = new();
    private readonly ConcurrentDictionary<int, LocalRpcStreamWriter<byte[]>> _writers = new();
    private readonly ConcurrentDictionary<int, LocalRpcPeer?> _peers = new();
    private int _running;
    private int _peakRunning;
    private long _workCompleted;

    /// <summary>The deadline each call saw when it started, by id; <see cref="TimeSpan.MaxValue"/> when it had none.</summary>
    internal IReadOnlyDictionary<int, TimeSpan> RemainingAtStart => _remainingAtStart;

    /// <summary>The stream-lane writer of each Subscribe call, by id.</summary>
    internal IReadOnlyDictionary<int, LocalRpcStreamWriter<byte[]>> Writers => _writers;

    /// <summary>The peer each WhoAmI call read, by id.</summary>
    internal IReadOnlyDictionary<int, LocalRpcPeer?> Peers => _peers;

    /// <summary>Released Work calls; a Work call with a hold of -1 waits for this.</summary>
    internal TaskCompletionSource Gate { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    internal int Running => Volatile.Read(ref _running);

    internal int PeakRunning => Volatile.Read(ref _peakRunning);

    internal long WorkCompleted => Interlocked.Read(ref _workCompleted);

    internal static byte[] WorkRequest(int id, int holdMilliseconds)
    {
        var request = new byte[8];
        BinaryPrimitives.WriteInt32BigEndian(request, id);
        BinaryPrimitives.WriteInt32BigEndian(request.AsSpan(4), holdMilliseconds);
        return request;
    }

    internal static byte[] IdRequest(int id)
    {
        var request = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(request, id);
        return request;
    }

    internal static byte[] SubscribeRequest(int id, SubscribeMode mode, int intervalMilliseconds = 0, int count = 0, int size = 0)
    {
        var request = new byte[17];
        BinaryPrimitives.WriteInt32BigEndian(request, id);
        request[4] = (byte)mode;
        BinaryPrimitives.WriteInt32BigEndian(request.AsSpan(5), intervalMilliseconds);
        BinaryPrimitives.WriteInt32BigEndian(request.AsSpan(9), count);
        BinaryPrimitives.WriteInt32BigEndian(request.AsSpan(13), size);
        return request;
    }

    public override async Task<byte[]> Work(byte[] request, ServerCallContext context)
    {
        var id = BinaryPrimitives.ReadInt32BigEndian(request);
        var hold = BinaryPrimitives.ReadInt32BigEndian(request.AsSpan(4));
        Record(id, context);
        Enter();
        try
        {
            if (hold < 0)
            {
                await Gate.Task.WaitAsync(context.CancellationToken).ConfigureAwait(false);
            }
            else if (hold > 0)
            {
                await Task.Delay(hold, context.CancellationToken).ConfigureAwait(false);
            }

            _ = Interlocked.Increment(ref _workCompleted);
            return IdRequest(id);
        }
        finally
        {
            _ = Interlocked.Decrement(ref _running);
        }
    }

    public override async Task<byte[]> Wait(byte[] request, ServerCallContext context)
    {
        var id = BinaryPrimitives.ReadInt32BigEndian(request);
        Record(id, context);
        await Task.Delay(Timeout.InfiniteTimeSpan, context.CancellationToken).ConfigureAwait(false);
        return [];
    }

    public override Task<byte[]> WhoAmI(byte[] request, ServerCallContext context)
    {
        var id = BinaryPrimitives.ReadInt32BigEndian(request);
        Record(id, context);
        var peer = context.GetLocalRpcPeer();
        _peers[id] = peer;
        return Task.FromResult(Encoding.UTF8.GetBytes(peer is null ? "none" : peer.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture)));
    }

    public override async Task Subscribe(byte[] request, IServerStreamWriter<byte[]> responseStream, ServerCallContext context)
    {
        var id = BinaryPrimitives.ReadInt32BigEndian(request);
        var mode = (SubscribeMode)request[4];
        var interval = BinaryPrimitives.ReadInt32BigEndian(request.AsSpan(5));
        var count = BinaryPrimitives.ReadInt32BigEndian(request.AsSpan(9));
        var size = BinaryPrimitives.ReadInt32BigEndian(request.AsSpan(13));
        Record(id, context);
        await using var stream = context.OpenLocalRpcStream(responseStream);
        _writers[id] = stream;
        switch (mode)
        {
            case SubscribeMode.Heartbeat:
                long sequence = 0;
                while (!stream.Ended.IsCancellationRequested)
                {
                    _ = stream.TryWrite(Heartbeat(++sequence));
                    try
                    {
                        await Task.Delay(interval, stream.Ended).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                }

                break;
            case SubscribeMode.Burst:
                for (var index = 0; index < count; index++)
                {
                    var message = new byte[Math.Max(size, 8)];
                    BinaryPrimitives.WriteInt64BigEndian(message, index);
                    if (!stream.TryWrite(message))
                    {
                        break;
                    }

                    if (interval > 0)
                    {
                        try
                        {
                            await Task.Delay(interval, stream.Ended).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException)
                        {
                            break;
                        }
                    }
                }

                break;
            default:
                try
                {
                    await Task.Delay(Timeout.InfiniteTimeSpan, stream.Ended).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // The stream ended.
                }

                break;
        }

        await stream.CompleteAsync().ConfigureAwait(false);
    }

    public override async Task Feed(byte[] request, IServerStreamWriter<byte[]> responseStream, ServerCallContext context)
    {
        var id = BinaryPrimitives.ReadInt32BigEndian(request);
        Record(id, context);
        await responseStream.WriteAsync(Heartbeat(1)).ConfigureAwait(false);
        await Task.Delay(Timeout.InfiniteTimeSpan, context.CancellationToken).ConfigureAwait(false);
    }

    internal static byte[] Heartbeat(long sequence)
    {
        var message = new byte[16];
        BinaryPrimitives.WriteInt64BigEndian(message, sequence);
        BinaryPrimitives.WriteInt64BigEndian(message.AsSpan(8), DateTime.UtcNow.Ticks);
        return message;
    }

    private void Record(int id, ServerCallContext context) =>
        _remainingAtStart[id] = context.Deadline == DateTime.MaxValue ? TimeSpan.MaxValue : context.Deadline - DateTime.UtcNow;

    private void Enter()
    {
        var now = Interlocked.Increment(ref _running);
        int peak;
        while (now > (peak = Volatile.Read(ref _peakRunning)) && Interlocked.CompareExchange(ref _peakRunning, now, peak) != peak)
        {
        }
    }
}

/// <summary>Resolves every offline (in-memory) service-mode connection to a fixed answer; the OS resolver is exercised by the opt-in checks.</summary>
internal sealed class FixedPeerResolver(Func<LocalRpcPeerResolution> answer) : LocalRpcPeerResolver
{
    private int _calls;

    internal int Calls => Volatile.Read(ref _calls);

    internal static LocalRpcPeer CurrentProcess { get; } = new(Environment.ProcessId, DateTimeOffset.UtcNow, "S-1-5-21-1-2-3-1001", null, "/test/peer")
    {
        Process = LocalRpcProcessIdentity.Current,
    };

    internal override LocalRpcPeerResolution Resolve(Stream stream, LocalRpcAcceptMoment accepted)
    {
        _ = Interlocked.Increment(ref _calls);
        return answer();
    }
}

/// <summary>
/// A service-mode server with the probe: over the platform's real well-known endpoint (opt-in OS checks) or over supplied in-memory streams
/// with a fixed peer resolver (offline tests that run in hosted CI).
/// </summary>
internal sealed class ServiceHarness : IAsyncDisposable
{
    internal static readonly TimeSpan Patience = TimeSpan.FromSeconds(30);

    private readonly LocalRpcStreamSupplier? _supplier;
    private readonly DirectoryInfo? _root;

    private ServiceHarness(LocalRpcServer server, ServiceProbeService probe, LocalRpcEndpoint? endpoint, LocalRpcStreamSupplier? supplier, DirectoryInfo? root)
    {
        Server = server;
        Probe = probe;
        Endpoint = endpoint;
        _supplier = supplier;
        _root = root;
    }

    internal LocalRpcServer Server { get; }

    internal ServiceProbeService Probe { get; }

    internal LocalRpcEndpoint? Endpoint { get; }

    /// <summary>The root directory of a Unix socket endpoint (its parent's parent), created for the test and removed with it.</summary>
    internal string? Root => _root?.FullName;

    /// <summary>Starts a service-mode server on a fresh well-known endpoint of this platform.</summary>
    internal static async Task<ServiceHarness> StartOsAsync(
        Action<LocalRpcServerBuilder>? configure = null,
        CancellationToken cancellationToken = default)
    {
        DirectoryInfo? root = null;
        LocalRpcEndpoint endpoint;
        if (OperatingSystem.IsWindows())
        {
            endpoint = LocalRpcEndpoint.NamedPipe("af-svc-" + Guid.NewGuid().ToString("N"));
        }
        else
        {
            // The parent is owner-only like $XDG_RUNTIME_DIR; the library creates the socket directory itself.
            root = Directory.CreateTempSubdirectory("afsvc-");
            endpoint = LocalRpcEndpoint.UnixDomainSocket(Path.Combine(root.FullName, "arcforges", "node.sock"));
        }

        var probe = new ServiceProbeService();
        var builder = LocalRpcServer.CreateBuilder(endpoint).AddService(probe);
        builder.Options = new LocalRpcServerOptions { Mode = LocalRpcServerMode.Service };
        configure?.Invoke(builder);
        var server = builder.Build();
        try
        {
            await server.StartAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await server.DisposeAsync().ConfigureAwait(false);
            root?.Delete(recursive: true);
            throw;
        }

        return new ServiceHarness(server, probe, endpoint, null, root);
    }

    /// <summary>Starts a service-mode server over supplied in-memory streams whose peers <paramref name="resolver"/> names.</summary>
    internal static async Task<ServiceHarness> StartOfflineAsync(
        LocalRpcPeerResolver resolver,
        Action<LocalRpcServerBuilder>? configure = null,
        TimeProvider? time = null,
        CancellationToken cancellationToken = default)
    {
        var supplier = new LocalRpcStreamSupplier();
        var probe = new ServiceProbeService();
        var builder = LocalRpcServer.CreateBuilder(supplier).AddService(probe).UsePeerResolver(resolver);
        builder.Options = new LocalRpcServerOptions { Mode = LocalRpcServerMode.Service };
        if (time is not null)
        {
            _ = builder.UseTimeProvider(time);
        }

        configure?.Invoke(builder);
        var server = builder.Build();
        await server.StartAsync(cancellationToken).ConfigureAwait(false);
        return new ServiceHarness(server, probe, null, supplier, null);
    }

    /// <summary>A client channel: one HTTP/2 connection to the server.</summary>
    internal LocalRpcClientChannel NewChannel()
    {
        if (Endpoint is not null)
        {
            return LocalRpcClientChannel.Create(Endpoint);
        }

        return LocalRpcClientChannel.CreateFromStreams(async _ =>
        {
            var (client, server) = InMemoryDuplexStream.CreatePair();
            if (!_supplier!.TrySupply(server))
            {
                await server.DisposeAsync().ConfigureAwait(false);
                await client.DisposeAsync().ConfigureAwait(false);
                throw new InvalidOperationException("The supplier refused a stream.");
            }

            return client;
        });
    }

    internal static async Task WaitUntilAsync(Func<bool> condition, string what, CancellationToken cancellationToken, TimeSpan? patience = null, Func<string>? describe = null)
    {
        var watch = Stopwatch.StartNew();
        while (!condition())
        {
            if (watch.Elapsed > (patience ?? Patience))
            {
                throw new TimeoutException("Timed out waiting for " + what + "." + (describe is null ? string.Empty : " " + describe()));
            }

            await Task.Delay(10, cancellationToken).ConfigureAwait(false);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await Server.DisposeAsync().ConfigureAwait(false);
        if (_root is not null && _root.Exists)
        {
            _root.Delete(recursive: true);
        }
    }
}

/// <summary>Calls the probe over one channel.</summary>
internal sealed class ServiceClient(CallInvoker invoker)
{
    internal CallInvoker Invoker { get; } = invoker;

    internal AsyncUnaryCall<byte[]> Work(int id, int holdMilliseconds, DateTime? deadline = null, CancellationToken cancellation = default) =>
        Invoker.AsyncUnaryCall(ServiceProbe.Work, null, new CallOptions(deadline: deadline, cancellationToken: cancellation), ServiceProbeService.WorkRequest(id, holdMilliseconds));

    internal AsyncUnaryCall<byte[]> Wait(int id, DateTime? deadline = null, CancellationToken cancellation = default) =>
        Invoker.AsyncUnaryCall(ServiceProbe.Wait, null, new CallOptions(deadline: deadline, cancellationToken: cancellation), ServiceProbeService.IdRequest(id));

    internal AsyncUnaryCall<byte[]> WhoAmI(int id) =>
        Invoker.AsyncUnaryCall(ServiceProbe.WhoAmI, null, new CallOptions(deadline: DateTime.UtcNow + ServiceHarness.Patience), ServiceProbeService.IdRequest(id));

    internal AsyncServerStreamingCall<byte[]> Subscribe(byte[] request, DateTime? deadline = null, CancellationToken cancellation = default) =>
        Invoker.AsyncServerStreamingCall(ServiceProbe.Subscribe, null, new CallOptions(deadline: deadline, cancellationToken: cancellation), request);

    internal AsyncServerStreamingCall<byte[]> Feed(int id, DateTime? deadline = null, CancellationToken cancellation = default) =>
        Invoker.AsyncServerStreamingCall(ServiceProbe.Feed, null, new CallOptions(deadline: deadline, cancellationToken: cancellation), ServiceProbeService.IdRequest(id));

    /// <summary>The RPC failure a call ends with; fails when it succeeds or does not end within the patience.</summary>
    internal static async Task<RpcException> FailureAsync(Task call)
    {
        try
        {
            await call.WaitAsync(ServiceHarness.Patience).ConfigureAwait(false);
        }
        catch (RpcException exception)
        {
            return exception;
        }

        throw new InvalidOperationException("The call was expected to fail.");
    }

    /// <summary>Reads a stream to its end; returns the messages read and the failure that ended it, if any.</summary>
    internal static async Task<(int Messages, RpcException? Failure)> DrainAsync(AsyncServerStreamingCall<byte[]> call, CancellationToken cancellationToken)
    {
        var messages = 0;
        try
        {
            while (await call.ResponseStream.MoveNext(cancellationToken).ConfigureAwait(false))
            {
                messages++;
            }

            return (messages, null);
        }
        catch (RpcException exception)
        {
            return (messages, exception);
        }
    }
}
