// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Security.Principal;
using ArcForges.LocalRpc;
using Grpc.Core;

/// <summary>
/// The Native AOT probe of the LocalRpc service-endpoint mode (AF-DP-01). Published with Native AOT (trim analysis full, warnings as
/// errors) it compiles every service-mode path of the library into a native executable; run, it serves one service-mode endpoint of this
/// platform and calls it from the same process: the peer identity of the connection (Windows pipe client process and token user, Linux
/// <c>SO_PEERCRED</c>), a raised per-method deadline, a stream-lane call with owner heartbeats beside data calls, a stream-lane refusal, and the
/// pipe's access list on Windows or the socket modes on Linux. CI publishes it (compile only) and never runs it.
/// </summary>
internal static class Program
{
    [SuppressMessage("Design", "CA1031", Justification = "This executable is a test boundary; every failure is reported with a failing exit code.")]
    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (args.Length > 0 && args[0] == WrongUser.ServeArgument)
            {
                return await WrongUser.ServeAsync(args.Contains("--expose-socket")).ConfigureAwait(false);
            }

            if (args.Length > 0 && args[0] == WrongUser.ConnectArgument)
            {
                return await WrongUser.ConnectAsync(args[1..]).ConfigureAwait(false);
            }

            if (RuntimeFeature.IsDynamicCodeSupported)
            {
                throw new InvalidOperationException("Run the published Native AOT executable: dotnet publish tests/LocalRpcServiceAotTests/LocalRpcServiceAotTests.csproj -c Release -r <win-x64|linux-x64>.");
            }

            if (!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux())
            {
                throw new PlatformNotSupportedException("Service mode runs on Windows and Linux.");
            }

            Console.WriteLine(await RunAsync().ConfigureAwait(false));
            return 0;
        }
        catch (Exception exception)
        {
            await Console.Error.WriteLineAsync("AF-DP-01 AOT probe failed: " + exception).ConfigureAwait(false);
            return 1;
        }
    }

    private static async Task<string> RunAsync()
    {
        DirectoryInfo? root = null;
        LocalRpcEndpoint endpoint;
        if (OperatingSystem.IsWindows())
        {
            endpoint = LocalRpcEndpoint.NamedPipe("af-svc-aot-" + Guid.NewGuid().ToString("N"));
        }
        else
        {
            root = Directory.CreateTempSubdirectory("afsvcaot-");
            endpoint = LocalRpcEndpoint.UnixDomainSocket(Path.Combine(root.FullName, "arcforges", "node.sock"));
        }

        try
        {
            var service = new ProbeService();
            LocalRpcPeer? decided = null;
            var builder = LocalRpcServer.CreateBuilder(endpoint)
                .AddService(service)
                .RegisterMethod(Probe.Work, new LocalRpcCallProfile(TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60)))
                .RegisterStream(Probe.Subscribe, new LocalRpcStreamProfile { HeartbeatInterval = TimeSpan.FromMilliseconds(200) })
                .AuthorizeConnections(connection =>
                {
                    decided = connection.Peer;
                    return connection.Peer is not null;
                });
            builder.Options = new LocalRpcServerOptions { Mode = LocalRpcServerMode.Service };
            builder.Limits = LocalRpcLimits.ServiceDefaults with { MaxStreamCallsPerConnection = 1 };
            await using var server = builder.Build();
            await server.StartAsync().ConfigureAwait(false);
            await using var channel = LocalRpcClientChannel.Create(endpoint);
            var invoker = channel.CallInvoker;

            // Peer identity, seen by the decision and by the handler.
            var answer = await invoker.AsyncUnaryCall(Probe.Work, null, new CallOptions(), [1]).ResponseAsync.ConfigureAwait(false);
            var peer = decided ?? throw new InvalidOperationException("The connection decision saw no peer.");
            Require(service.Peer == peer, "the handler's peer is the decision's peer");
            Require(peer.ProcessId == Environment.ProcessId, "the peer is this process");
            Require(peer.Process.ProcessId == LocalRpcProcessIdentity.Current.ProcessId && Math.Abs(peer.Process.StartTimeUtcTicks - LocalRpcProcessIdentity.Current.StartTimeUtcTicks) <= TimeSpan.TicksPerSecond * 2, "the peer's start time names this process");
            Require(string.Equals(Path.GetFullPath(peer.ExecutablePath ?? string.Empty), Path.GetFullPath(Environment.ProcessPath!), OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal), "the peer's executable is this executable");
            if (OperatingSystem.IsWindows())
            {
                using var current = WindowsIdentity.GetCurrent();
                Require(peer.UserSid == current.User!.Value && peer.Uid is null, "the peer's token user is this user");
            }
            else
            {
                Require(peer.Uid is not null && peer.UserSid is null, "the peer's SO_PEERCRED uid is read");
                Require(File.GetUnixFileMode(Path.GetDirectoryName(endpoint.Address)!) == (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute), "the socket directory is 0700");
                Require(File.GetUnixFileMode(endpoint.Address) == (UnixFileMode.UserRead | UnixFileMode.UserWrite), "the socket is 0600");
            }

            // The raised per-method deadline: no declared deadline gives the profile's 60 s, above the 30 s data cap.
            var remaining = TimeSpan.FromMilliseconds(BinaryPrimitives.ReadInt64BigEndian(answer));
            Require(remaining > TimeSpan.FromSeconds(55) && remaining <= TimeSpan.FromSeconds(60), "the profiled deadline is 60 s (" + remaining + ")");

            // A stream-lane call: owner heartbeats arrive while data calls run beside it; a second stream on the connection is refused at once.
            using var stop = new CancellationTokenSource();
            using var stream = invoker.AsyncServerStreamingCall(Probe.Subscribe, null, new CallOptions(cancellationToken: stop.Token), [2]);
            var heartbeats = 0;
            var watch = Stopwatch.StartNew();
            var data = Enumerable.Range(0, 16).Select(_ => invoker.AsyncUnaryCall(Probe.Work, null, new CallOptions(), [3]).ResponseAsync).ToArray();
            while (heartbeats < 5 && await stream.ResponseStream.MoveNext(stop.Token).ConfigureAwait(false))
            {
                heartbeats++;
            }

            _ = await Task.WhenAll(data).ConfigureAwait(false);
            using (var refused = invoker.AsyncServerStreamingCall(Probe.Subscribe, null, new CallOptions(), [2]))
            {
                try
                {
                    _ = await refused.ResponseStream.MoveNext().ConfigureAwait(false);
                    throw new InvalidOperationException("A second stream on the connection was admitted.");
                }
                catch (RpcException exception) when (LocalRpcRefusal.TryRead(exception, out var refusal) && refusal!.Reason == LocalRpcRefusalReason.StreamLaneFull)
                {
                    // The stream lane holds one stream per connection in this probe.
                }
            }

            var snapshot = server.GetServiceSnapshot();
            Require(snapshot.StreamsActive == 1 && snapshot.PeersAdmitted == 1, "one stream on one admitted connection");
            await stop.CancelAsync().ConfigureAwait(false);
            return "PASS: AF-DP-01 service mode under Native AOT on " + (OperatingSystem.IsWindows() ? "Windows (named pipe)" : "Linux (Unix socket)")
                + ": peer " + peer.ProcessId + " " + (peer.UserSid ?? "uid " + peer.Uid) + ", profiled deadline " + remaining.TotalSeconds.ToString("F1", System.Globalization.CultureInfo.InvariantCulture)
                + " s, " + heartbeats + " heartbeats in " + watch.ElapsedMilliseconds + " ms beside 16 data calls, second stream refused stream-lane-full.";
        }
        finally
        {
            root?.Delete(recursive: true);
        }
    }

    private static void Require(bool condition, string what)
    {
        if (!condition)
        {
            throw new InvalidOperationException("Check failed: " + what + ".");
        }
    }
}

/// <summary>A hand-written test-only service shaped like generated code: one unary method and one server-streaming method.</summary>
internal static class Probe
{
    internal const string ServiceName = "arcforges.test.service.v1.AotProbe";

    private static readonly Marshaller<byte[]> Bytes = Marshallers.Create(value => value, value => value);

    internal static readonly Method<byte[], byte[]> Work = new(MethodType.Unary, ServiceName, "Work", Bytes, Bytes);

    internal static readonly Method<byte[], byte[]> Subscribe = new(MethodType.ServerStreaming, ServiceName, "Subscribe", Bytes, Bytes);

    public static void BindService(ServiceBinderBase binder, ProbeBase? service)
    {
        ArgumentNullException.ThrowIfNull(binder);
        binder.AddMethod(Work, service is null ? null : new UnaryServerMethod<byte[], byte[]>(service.Work));
        binder.AddMethod(Subscribe, service is null ? null : new ServerStreamingServerMethod<byte[], byte[]>(service.Subscribe));
    }

    [BindServiceMethod(typeof(Probe), nameof(BindService))]
    internal abstract class ProbeBase
    {
        public abstract Task<byte[]> Work(byte[] request, ServerCallContext context);

        public abstract Task Subscribe(byte[] request, IServerStreamWriter<byte[]> responseStream, ServerCallContext context);
    }
}

internal sealed class ProbeService : Probe.ProbeBase
{
    internal LocalRpcPeer? Peer { get; private set; }

    public override async Task<byte[]> Work(byte[] request, ServerCallContext context)
    {
        Peer = context.GetLocalRpcPeer();
        var remaining = context.Deadline == DateTime.MaxValue ? TimeSpan.MaxValue : context.Deadline - DateTime.UtcNow;
        await Task.Delay(50, context.CancellationToken).ConfigureAwait(false);
        var answer = new byte[8];
        BinaryPrimitives.WriteInt64BigEndian(answer, (long)remaining.TotalMilliseconds);
        return answer;
    }

    public override async Task Subscribe(byte[] request, IServerStreamWriter<byte[]> responseStream, ServerCallContext context)
    {
        await using var stream = context.OpenLocalRpcStream(responseStream);
        while (!stream.Ended.IsCancellationRequested)
        {
            _ = stream.TryWrite(BitConverter.GetBytes(DateTime.UtcNow.Ticks));
            try
            {
                await Task.Delay(200, stream.Ended).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        await stream.CompleteAsync().ConfigureAwait(false);
    }
}
