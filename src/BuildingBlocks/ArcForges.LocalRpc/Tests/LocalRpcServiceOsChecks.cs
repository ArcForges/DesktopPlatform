// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Grpc.Core;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// Service mode (AF-DP-01) on the real operating system: explicit local opt-in checks (ARCFORGES_LOCALRPC_OS_STREAMS=1), skipped by default
/// and never run in hosted CI. They use a real Named Pipe on Windows and a real Unix domain socket on Linux, real processes and the real
/// clock; nothing here is faked. A pass names only the operating system it ran on. Refusal of a second OS account cannot be shown under
/// one account (acceptance register AR-02); these checks prove the access list, the directory and socket modes and the peer checks that
/// the second account would meet.
/// </summary>
[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcServiceOsChecks
{
    private const string OptIn = "Explicit local OS service-mode checks only (ARCFORGES_LOCALRPC_OS_STREAMS=1).";
    private const string LongOptIn = "Explicit local 15-minute service-mode run only (ARCFORGES_LOCALRPC_OS_STREAMS=1 and ARCFORGES_LOCALRPC_LONG_STREAM=1).";
    private const int FileGenericReadWrite = 0x0012019F;

    public static bool Enabled => LocalRpcOsStreamChecks.Enabled && (OperatingSystem.IsWindows() || OperatingSystem.IsLinux());

    public static bool WindowsEnabled => Enabled && OperatingSystem.IsWindows();

    public static bool LinuxEnabled => Enabled && OperatingSystem.IsLinux();

    public static bool LongEnabled => Enabled && Environment.GetEnvironmentVariable("ARCFORGES_LOCALRPC_LONG_STREAM") == "1";

    // ---- endpoint access ----

    [Fact(Skip = OptIn, SkipUnless = nameof(WindowsEnabled))]
    [SupportedOSPlatform("windows")]
    public async Task EveryServicePipeInstanceIsOwnedByTheUserGrantsOnlyTheUserAndSystemAndDeniesTheNetwork()
    {
        var ct = TestContext.Current.CancellationToken;
        var name = "af-svc-acl-" + Guid.NewGuid().ToString("N");
        await using var source = NamedPipeAcceptSource.BindService(name);
        var user = WindowsIdentity.GetCurrent().User!;
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var network = new SecurityIdentifier(WellKnownSidType.NetworkSid, null);

        // The first instance and two later ones: every instance carries the same explicit list.
        for (var instance = 0; instance < 3; instance++)
        {
            var accepted = source.AcceptAsync(ct).AsTask();
            await using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly, TokenImpersonationLevel.Anonymous);
            await client.ConnectAsync(ct);
            await using var stream = await accepted.WaitAsync(ServiceHarness.Patience, ct);
            var security = Assert.IsType<NamedPipeServerStream>(stream).GetAccessControl();

            Assert.Equal(user, security.GetOwner(typeof(SecurityIdentifier)));
            Assert.True(security.AreAccessRulesProtected);
            var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)).Cast<PipeAccessRule>().ToArray();
            Assert.Equal(3, rules.Length);
            Assert.All(rules, rule => Assert.False(rule.IsInherited));
            var deny = Assert.Single(rules, rule => rule.AccessControlType == AccessControlType.Deny);
            Assert.Equal(network, deny.IdentityReference);
            Assert.Equal(PipeAccessRights.FullControl, deny.PipeAccessRights & PipeAccessRights.FullControl);
            var allowed = rules.Where(rule => rule.AccessControlType == AccessControlType.Allow).ToArray();
            Assert.Equal(new[] { system.Value, user.Value }.Order(), allowed.Select(rule => rule.IdentityReference.Value).Order());
            Assert.All(allowed, rule => Assert.Equal(FileGenericReadWrite, (int)rule.PipeAccessRights));
        }
    }

    [Fact(Skip = OptIn, SkipUnless = nameof(WindowsEnabled))]
    [SupportedOSPlatform("windows")]
    public async Task AServicePipeRefusesAClientThatComesThroughTheNetworkRedirector()
    {
        var ct = TestContext.Current.CancellationToken;

        // Control: a parent-child pipe (no reject flag, no network deny) is reachable through \\127.0.0.1\pipe, so the path works here.
        var plainName = "af-svc-plain-" + Guid.NewGuid().ToString("N");
        await using (var plain = NamedPipeAcceptSource.Bind(plainName))
        {
            var accepted = plain.AcceptAsync(ct).AsTask();
            Assert.Null(await ConnectThroughRedirectorAsync(plainName, ct));
            await (await accepted.WaitAsync(ServiceHarness.Patience, ct))!.DisposeAsync();
        }

        // The service pipe itself.
        var serviceName = "af-svc-remote-" + Guid.NewGuid().ToString("N");
        await using (var source = NamedPipeAcceptSource.BindService(serviceName))
        {
            var refused = await ConnectThroughRedirectorAsync(serviceName, ct);
            Assert.IsType<UnauthorizedAccessException>(refused);
        }

        // Which barrier refuses it: PIPE_REJECT_REMOTE_CLIENTS. The same native pipe with the flag refuses the redirector client with or without
        // the NETWORK deny, and without the flag admits it with or without the deny. (A loopback redirector client does not present the
        // NETWORK SID here, so the deny entry, which guards against network logons from another machine, is not exercised on one workstation.)
        var withoutNetworkDeny = UserAndSystemOnly();
        await AssertRedirectorOutcomeAsync(LocalRpcWindowsNative.PipeRejectRemoteClients, LocalRpcWindowsNative.ServicePipeSecurity(), admitted: false, ct);
        await AssertRedirectorOutcomeAsync(LocalRpcWindowsNative.PipeRejectRemoteClients, withoutNetworkDeny, admitted: false, ct);
        await AssertRedirectorOutcomeAsync(0, LocalRpcWindowsNative.ServicePipeSecurity(), admitted: true, ct);
        await AssertRedirectorOutcomeAsync(0, withoutNetworkDeny, admitted: true, ct);
    }

    [Fact(Skip = OptIn, SkipUnless = nameof(WindowsEnabled))]
    [SupportedOSPlatform("windows")]
    public async Task AServicePipeNameIsNeverSharedOrReplaced()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await ServiceHarness.StartOsAsync(cancellationToken: ct);
        var second = LocalRpcServer.CreateBuilder(harness.Endpoint!).AddService(new ServiceProbeService());
        second.Options = new LocalRpcServerOptions { Mode = LocalRpcServerMode.Service };
        await using var duplicate = second.Build();

        var failure = await Assert.ThrowsAnyAsync<Exception>(() => duplicate.StartAsync(ct));

        Assert.Contains(ExceptionChain(failure), exception => exception is IOException { Message: var message } && message.Contains("already in use", StringComparison.Ordinal));
        await using var channel = harness.NewChannel();
        _ = await new ServiceClient(channel.CallInvoker).WhoAmI(1).ResponseAsync.WaitAsync(ServiceHarness.Patience, ct);
    }

    [Fact(Skip = OptIn, SkipUnless = nameof(LinuxEnabled))]
    [SupportedOSPlatform("linux")]
    public async Task TheServiceSocketDirectoryIsCreatedOwnerOnlyAndTheSocketIsOwnerOnly()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await ServiceHarness.StartOsAsync(cancellationToken: ct);
        var socket = harness.Endpoint!.Address;
        var directory = Path.GetDirectoryName(socket)!;

        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(directory));
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(socket));
        Assert.Null(new DirectoryInfo(directory).LinkTarget);
        await using var channel = harness.NewChannel();
        _ = await new ServiceClient(channel.CallInvoker).WhoAmI(1).ResponseAsync.WaitAsync(ServiceHarness.Patience, ct);
        Assert.Equal(LocalRpcOsPeerResolver.CurrentEffectiveUid, harness.Probe.Peers[1]!.Uid);
    }

    [Fact(Skip = OptIn, SkipUnless = nameof(LinuxEnabled))]
    [SupportedOSPlatform("linux")]
    public async Task AServiceSocketIsRefusedInAnOpenOrLinkedDirectoryAndOnlyAStaleSocketIsReplaced()
    {
        var ct = TestContext.Current.CancellationToken;
        var root = Directory.CreateTempSubdirectory("afsvc-");
        try
        {
            // A directory another user could enter is refused, as for every socket of this library.
            var open = Directory.CreateDirectory(Path.Combine(root.FullName, "open"));
            File.SetUnixFileMode(open.FullName, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupExecute);
            Assert.Throws<UnauthorizedAccessException>(() => UnixSocketAcceptSource.BindService(Path.Combine(open.FullName, "s.sock"), 4));

            // A linked directory is refused even when its target is owner-only.
            var target = Directory.CreateDirectory(Path.Combine(root.FullName, "target"));
            File.SetUnixFileMode(target.FullName, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var link = Directory.CreateSymbolicLink(Path.Combine(root.FullName, "link"), target.FullName);
            Assert.Throws<UnauthorizedAccessException>(() => UnixSocketAcceptSource.BindService(Path.Combine(link.FullName, "s.sock"), 4));

            // A missing directory is created 0700.
            var path = Path.Combine(root.FullName, "made", "s.sock");
            await using (var made = UnixSocketAcceptSource.BindService(path, 4))
            {
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(Path.GetDirectoryName(path)!));
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));

                // A live server's socket is never replaced.
                Assert.Throws<IOException>(() => UnixSocketAcceptSource.BindService(path, 4));
            }

            // A socket whose server is gone is replaced: a real server process killed without cleanup leaves its socket behind (a socket this
            // process binds is unlinked by the runtime when it is closed, so it cannot leave one).
            using (var orphan = StartHelper("orphan|" + Path.Combine(root.FullName, "orphan-rt")))
            {
                var ready = (await orphan.StandardOutput.ReadLineAsync(ct).AsTask().WaitAsync(ServiceHarness.Patience, ct))!.Split(' ', 3);
                Assert.Equal("READY", ready[0]);
                var stalePath = LocalRpcLaunchDescriptor.Decode(Convert.FromBase64String(ready[1])).Endpoint!.Address;
                orphan.Kill(entireProcessTree: true);
                await orphan.WaitForExitAsync(ct);
                Assert.True(File.Exists(stalePath), "The killed server left its socket.");
                await using var replaced = UnixSocketAcceptSource.BindService(stalePath, 4);
                using var probe = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                await probe.ConnectAsync(new UnixDomainSocketEndPoint(stalePath), ct);
            }

            // A directory at the socket path is never touched.
            Directory.CreateDirectory(path);
            Assert.Throws<IOException>(() => UnixSocketAcceptSource.BindService(path, 4));
            Assert.True(Directory.Exists(path));
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Fact(Skip = OptIn, SkipUnless = nameof(Enabled))]
    public async Task TheWellKnownPerUserEndpointIsBoundAndReachedByServerAndClient()
    {
        var ct = TestContext.Current.CancellationToken;
        var fallback = Directory.CreateTempSubdirectory("afsvc-");
        var name = "t" + Guid.NewGuid().ToString("N")[..16];
        var endpoint = LocalRpcEndpoint.ForCurrentUserService(name, Path.Combine(fallback.FullName, "run"));
        var createdRuntimeDirectory = !OperatingSystem.IsWindows() && !Directory.Exists(Path.GetDirectoryName(endpoint.Address));
        try
        {
            var probe = new ServiceProbeService();
            var builder = LocalRpcServer.CreateBuilder(endpoint).AddService(probe);
            builder.Options = new LocalRpcServerOptions { Mode = LocalRpcServerMode.Service };
            await using (var server = builder.Build())
            {
                await server.StartAsync(ct);
                await using var channel = LocalRpcClientChannel.Create(LocalRpcEndpoint.ForCurrentUserService(name, Path.Combine(fallback.FullName, "run")));
                _ = await new ServiceClient(channel.CallInvoker).WhoAmI(1).ResponseAsync.WaitAsync(ServiceHarness.Patience, ct);
                Assert.Equal(Environment.ProcessId, probe.Peers[1]!.ProcessId);
            }

            if (!OperatingSystem.IsWindows())
            {
                Assert.False(File.Exists(endpoint.Address), "The listener removes the socket it created.");
            }
        }
        finally
        {
            fallback.Delete(recursive: true);
            if (createdRuntimeDirectory && Directory.Exists(Path.GetDirectoryName(endpoint.Address)) && !Directory.EnumerateFileSystemEntries(Path.GetDirectoryName(endpoint.Address)!).Any())
            {
                Directory.Delete(Path.GetDirectoryName(endpoint.Address)!);
            }
        }
    }

    // ---- connections ----

    [Fact(Skip = OptIn, SkipUnless = nameof(Enabled))]
    public async Task SixtyFourConnectionsAreServedAtOnceAndASixtyFifthWaitsForASlotWithoutBeingReset()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await ServiceHarness.StartOsAsync(cancellationToken: ct);
        var channels = Enumerable.Range(0, 65).Select(_ => harness.NewChannel()).ToList();
        try
        {
            // The connections open one after another (each holds a call before the next connects): the OS backlog stays 16, as for every
            // server of this library, and a simultaneous burst of more than about 16 connects is answered EAGAIN by Linux (a Named Pipe client
            // waits instead). Then all 64 are open and calling at once.
            var calls = new List<AsyncUnaryCall<byte[]>>();
            foreach (var (channel, index) in channels.Take(64).Select((channel, index) => (channel, index)))
            {
                calls.Add(new ServiceClient(channel.CallInvoker).Work(index, -1, DateTime.UtcNow + TimeSpan.FromMinutes(2), ct));
                await ServiceHarness.WaitUntilAsync(() => harness.Probe.Running == index + 1, "call " + index, ct, describe: () => Describe(harness));
            }

            await ServiceHarness.WaitUntilAsync(
                () => harness.Probe.Running == 64,
                "64 calls on 64 connections",
                ct,
                TimeSpan.FromMinutes(1),
                () => Describe(harness) + ", failed calls " + calls.Count(call => call.ResponseAsync.IsFaulted) + ": "
                    + calls.Where(call => call.ResponseAsync.IsFaulted).Select(call => call.ResponseAsync.Exception!.InnerException!.Message).FirstOrDefault());

            Assert.Equal(64, harness.Server.GetBoundsSnapshot().Peers);
            Assert.Equal(64, harness.Server.GetServiceSnapshot().PeersAdmitted);
            var waiting = new ServiceClient(channels[64].CallInvoker).Work(64, 0, DateTime.UtcNow + TimeSpan.FromMinutes(2), ct);
            await Task.Delay(TimeSpan.FromSeconds(2), ct);
            Assert.False(waiting.ResponseAsync.IsCompleted, "The 65th connection waits for a slot; it is not reset.");
            Assert.Equal(64, harness.Server.GetBoundsSnapshot().Peers);

            harness.Probe.Gate.SetResult();
            await Task.WhenAll(calls.Select(call => call.ResponseAsync)).WaitAsync(ServiceHarness.Patience, ct);
            Assert.False(waiting.ResponseAsync.IsCompleted, "A connection slot frees only when a connection closes.");
            await channels[0].DisposeAsync();
            channels.RemoveAt(0);
            _ = await waiting.ResponseAsync.WaitAsync(ServiceHarness.Patience, ct);
            Assert.Equal(65, harness.Server.GetServiceSnapshot().PeersAdmitted);
            Assert.All(harness.Server.GetServiceSnapshot().PeersDenied.Values, count => Assert.Equal(0, count));
        }
        finally
        {
            foreach (var channel in channels)
            {
                await channel.DisposeAsync();
            }
        }
    }

    // ---- peer identity ----

    [Fact(Skip = OptIn, SkipUnless = nameof(Enabled))]
    public async Task TheConnectionDecisionAndTheHandlerSeeThisProcessAsThePeer()
    {
        var ct = TestContext.Current.CancellationToken;
        LocalRpcConnectionInfo? decided = null;
        await using var harness = await ServiceHarness.StartOsAsync(builder => builder.AuthorizeConnections(connection =>
        {
            decided = connection;
            return true;
        }), ct);
        await using var channel = harness.NewChannel();

        _ = await new ServiceClient(channel.CallInvoker).WhoAmI(1).ResponseAsync.WaitAsync(ServiceHarness.Patience, ct);

        var peer = decided!.Peer!;
        Assert.Equal(peer, harness.Probe.Peers[1]);
        using var current = Process.GetCurrentProcess();
        Assert.Equal(Environment.ProcessId, peer.ProcessId);
        Assert.True(peer.Process.Names(LocalRpcProcessIdentity.Current), "The peer's process identity names this process.");
        Assert.InRange((peer.ProcessStartTime - new DateTimeOffset(current.StartTime.ToUniversalTime(), TimeSpan.Zero)).Duration(), TimeSpan.Zero, TimeSpan.FromSeconds(2));
        Assert.Equal(Path.GetFullPath(Environment.ProcessPath!), Path.GetFullPath(peer.ExecutablePath!), OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        if (OperatingSystem.IsWindows())
        {
            Assert.Equal(WindowsIdentity.GetCurrent().User!.Value, peer.UserSid);
            Assert.Null(peer.Uid);
        }
        else
        {
            Assert.Equal(LocalRpcLinuxProc.EffectiveUid(await File.ReadAllTextAsync("/proc/self/status", ct)), peer.Uid);
            Assert.Null(peer.UserSid);
        }
    }

    [Fact(Skip = OptIn, SkipUnless = nameof(Enabled))]
    public async Task APeerProcessThatExitsBetweenAcceptAndQueryIsDenied()
    {
        var ct = TestContext.Current.CancellationToken;
        Process? child = null;
        var reported = new List<int>();
        var resolver = new LocalRpcOsPeerResolver
        {
            BeforeProcessQuery = processId =>
            {
                lock (reported)
                {
                    reported.Add(processId);
                }

                // The child connects and leaves at once; the query runs only once it has exited.
                var started = Stopwatch.StartNew();
                while (Volatile.Read(ref child) is null && started.Elapsed < ServiceHarness.Patience)
                {
                    Thread.Sleep(10);
                }

                _ = child?.WaitForExit(ServiceHarness.Patience);
            },
        };
        await using var harness = await ServiceHarness.StartOsAsync(
            builder =>
            {
                _ = builder.UsePeerResolver(resolver);
                builder.Limits = LocalRpcLimits.ServiceDefaults with { AuthorizationTimeout = TimeSpan.FromSeconds(30) };
            },
            ct);
        var transport = OperatingSystem.IsWindows() ? "named-pipe" : "unix-socket";
        var owner = OperatingSystem.IsWindows() ? LocalRpcOsPeerResolver.CurrentUserSid! : LocalRpcOsPeerResolver.CurrentEffectiveUid!.Value.ToString(CultureInfo.InvariantCulture);

        using var process = StartHelper("wrong-user-connect|" + transport + "|" + harness.Endpoint!.Address + "|" + owner + "|admitted-control");
        Volatile.Write(ref child, process);
        var output = await process.StandardOutput.ReadToEndAsync(ct);
        await process.WaitForExitAsync(ct);

        Assert.Equal(0, process.ExitCode);
        Assert.Contains("ADMITTED", output, StringComparison.Ordinal);
        await ServiceHarness.WaitUntilAsync(() => harness.Server.GetServiceSnapshot().PeersDenied[LocalRpcPeerDenial.ProcessExited] == 1, "the denial of the exited peer", ct);
        lock (reported)
        {
            Assert.Equal([process.Id], reported);
        }

        Assert.Equal(0, harness.Server.GetServiceSnapshot().PeersAdmitted);
        Assert.Empty(harness.Probe.Peers);
    }

    [Fact(Skip = OptIn, SkipUnless = nameof(Enabled))]
    public async Task TheProcessQueryNamesALiveChildAndDeniesItWhenItIsNewerThanTheAcceptOrHasExited()
    {
        var ct = TestContext.Current.CancellationToken;
        var beforeChild = LocalRpcAcceptMoment.Now();
        await Task.Delay(TimeSpan.FromMilliseconds(1100), ct);
        using var child = StartHelper("sleep");
        Assert.Equal("READY", await child.StandardOutput.ReadLineAsync(ct).AsTask().WaitAsync(ServiceHarness.Patience, ct));
        var accepted = LocalRpcAcceptMoment.Now();

        var live = Query(child.Id, accepted);

        var peer = live.Peer!;
        Assert.Equal(LocalRpcPeerDenial.None, live.Denial);
        Assert.Equal(child.Id, peer.ProcessId);
        Assert.True(peer.Process.Names(LocalRpcProcessIdentity.FromProcess(child)));
        Assert.InRange((peer.ProcessStartTime - new DateTimeOffset(child.StartTime.ToUniversalTime(), TimeSpan.Zero)).Duration(), TimeSpan.Zero, TimeSpan.FromSeconds(2));
        Assert.Equal(Path.GetFullPath(Environment.ProcessPath!), Path.GetFullPath(peer.ExecutablePath!), OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        Assert.Equal(OperatingSystem.IsWindows() ? LocalRpcOsPeerResolver.CurrentUserSid : null, peer.UserSid);
        Assert.Equal(OperatingSystem.IsWindows() ? null : LocalRpcOsPeerResolver.CurrentEffectiveUid, peer.Uid);

        // A process that started after the accept cannot be the one that connected: its id was reused.
        Assert.Equal(LocalRpcPeerDenial.ProcessExited, Query(child.Id, beforeChild).Denial);

        child.Kill(entireProcessTree: true);
        await child.WaitForExitAsync(ct);
        Assert.Equal(LocalRpcPeerDenial.ProcessExited, Query(child.Id, accepted).Denial);
    }

    // ---- deadlines ----

    [Fact(Skip = OptIn, SkipUnless = nameof(Enabled))]
    public async Task AProfiledMethodRunsPastTheDataDeadlineCapAndAShorterProfileEndsItsCallsOnTheRealEndpoint()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await ServiceHarness.StartOsAsync(
            builder => builder
                .RegisterMethod(ServiceProbe.Work, new LocalRpcCallProfile(TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60)))
                .RegisterMethod(ServiceProbe.Wait, new LocalRpcCallProfile(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1))),
            ct);
        await using var channel = harness.NewChannel();
        var client = new ServiceClient(channel.CallInvoker);

        var watch = Stopwatch.StartNew();
        _ = await client.Work(1, 35_000, cancellation: ct).ResponseAsync.WaitAsync(TimeSpan.FromMinutes(2), ct);
        Assert.True(watch.Elapsed >= TimeSpan.FromSeconds(34), "A 35 s call ran past the 30 s data deadline cap.");
        _ = await client.Work(2, 0, DateTime.UtcNow + TimeSpan.FromSeconds(90), ct).ResponseAsync.WaitAsync(ServiceHarness.Patience, ct);
        _ = await client.WhoAmI(3).ResponseAsync.WaitAsync(ServiceHarness.Patience, ct);
        watch.Restart();
        var expired = await ServiceClient.FailureAsync(client.Wait(4, DateTime.UtcNow + TimeSpan.FromSeconds(20), ct).ResponseAsync);
        var waited = watch.Elapsed;

        Assert.InRange(harness.Probe.RemainingAtStart[1], TimeSpan.FromSeconds(55), TimeSpan.FromSeconds(60.5));
        Assert.InRange(harness.Probe.RemainingAtStart[2], TimeSpan.FromSeconds(55), TimeSpan.FromSeconds(60.5));
        Assert.InRange(harness.Probe.RemainingAtStart[3], TimeSpan.FromSeconds(25), TimeSpan.FromSeconds(30.5));
        Assert.Equal(StatusCode.DeadlineExceeded, expired.StatusCode);
        Assert.InRange(waited, TimeSpan.FromMilliseconds(800), TimeSpan.FromSeconds(10));
    }

    // ---- stream lane ----

    [Fact(Skip = OptIn, SkipUnless = nameof(Enabled))]
    public async Task AStreamWithHeartbeatsRunsBesideSixteenDataCallsOnTheRealEndpoint()
    {
        await StreamBesideDataCallsAsync(TimeSpan.FromSeconds(20), TimeSpan.FromSeconds(1), checkServiceIdle: false, TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// The acceptance run: a 15-minute stream with the design's 15 s heartbeats beside 16 concurrent data calls on the same connection, with
    /// a second connection left idle to show the 10-minute service idle close at its real value. Opt-in on its own because it takes 15 minutes.
    /// </summary>
    [Fact(Skip = LongOptIn, SkipUnless = nameof(LongEnabled))]
    public async Task AFifteenMinuteStreamWithHeartbeatsRunsBesideSixteenDataCallsAndAnIdleConnectionClosesAtTenMinutes()
    {
        await StreamBesideDataCallsAsync(TimeSpan.FromMinutes(15), TimeSpan.FromSeconds(15), checkServiceIdle: true, TestContext.Current.CancellationToken);
    }

    [Fact(Skip = OptIn, SkipUnless = nameof(Enabled))]
    public async Task AReaderThatFallsBehindOverflowsGetsResourceExhaustedAndResubscribesOnTheRealEndpoint()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await ServiceHarness.StartOsAsync(
            builder => builder.RegisterStream(ServiceProbe.Subscribe, new LocalRpcStreamProfile { MaxBufferedMessages = 32 }),
            ct);
        await using var channel = harness.NewChannel();
        var client = new ServiceClient(channel.CallInvoker);
        using var burst = client.Subscribe(ServiceProbeService.SubscribeRequest(1, SubscribeMode.Burst, 1, count: 1_000_000, size: 16 * 1024), cancellation: ct);

        await ServiceHarness.WaitUntilAsync(() => harness.Probe.Writers.TryGetValue(1, out var writer) && writer.EndReason != LocalRpcStreamEndReason.None, "the overflow", ct);
        Assert.Equal(LocalRpcStreamEndReason.Overflow, harness.Probe.Writers[1].EndReason);
        var (messages, failure) = await ServiceClient.DrainAsync(burst, ct);

        Assert.Equal(StatusCode.ResourceExhausted, failure!.StatusCode);
        Assert.True(LocalRpcStreamEnd.TryRead(failure, out var reason));
        Assert.Equal(LocalRpcStreamEndReason.Overflow, reason);
        Assert.InRange(messages, 1, 999_999);
        using var fresh = client.Subscribe(ServiceProbeService.SubscribeRequest(2, SubscribeMode.Heartbeat, 50), cancellation: ct);
        Assert.True(await fresh.ResponseStream.MoveNext(ct));
        Assert.True(await fresh.ResponseStream.MoveNext(ct));
        Assert.Equal(1, harness.Server.GetServiceSnapshot().StreamsEnded[LocalRpcStreamEndReason.Overflow]);
    }

    [Fact(Skip = OptIn, SkipUnless = nameof(Enabled))]
    public async Task AReaderThatStopsReadingIsResetAndItsConnectionStillServesCallsOnTheRealEndpoint()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await ServiceHarness.StartOsAsync(
            builder => builder.RegisterStream(ServiceProbe.Subscribe, new LocalRpcStreamProfile { MaxBufferedMessages = 65_536, RequireReads = TimeSpan.FromSeconds(2) }),
            ct);
        await using var channel = harness.NewChannel();
        var client = new ServiceClient(channel.CallInvoker);
        using var stalled = client.Subscribe(ServiceProbeService.SubscribeRequest(1, SubscribeMode.Burst, count: 8192, size: 16 * 1024), cancellation: ct);

        await ServiceHarness.WaitUntilAsync(() => harness.Probe.Writers.TryGetValue(1, out var writer) && writer.EndReason != LocalRpcStreamEndReason.None, "the stalled reader", ct);

        Assert.Equal(LocalRpcStreamEndReason.ReadsStalled, harness.Probe.Writers[1].EndReason);
        var (_, failure) = await ServiceClient.DrainAsync(stalled, ct);
        Assert.NotNull(failure);
        _ = await client.Work(2, 0, cancellation: ct).ResponseAsync.WaitAsync(ServiceHarness.Patience, ct);
    }

    // ---- idle rules ----

    [Fact(Skip = OptIn, SkipUnless = nameof(Enabled))]
    public async Task OnTheRealEndpointAConnectionWithAnOpenStreamStaysAndOneWithoutClosesWhenIdle()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await ServiceHarness.StartOsAsync(
            builder =>
            {
                builder.Limits = LocalRpcLimits.ServiceDefaults with { IdleTimeout = TimeSpan.FromSeconds(2) };
                _ = builder.RegisterStream(ServiceProbe.Subscribe, new LocalRpcStreamProfile());
            },
            ct);
        await using var streaming = harness.NewChannel();
        await using var idle = harness.NewChannel();
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(ct);
        using var silent = new ServiceClient(streaming.CallInvoker).Subscribe(ServiceProbeService.SubscribeRequest(1, SubscribeMode.Silent), cancellation: cancel.Token);
        _ = await new ServiceClient(idle.CallInvoker).Work(2, 0, cancellation: ct).ResponseAsync.WaitAsync(ServiceHarness.Patience, ct);
        await ServiceHarness.WaitUntilAsync(() => harness.Server.GetServiceSnapshot().StreamsActive == 1, "the stream to open", ct, describe: () => Describe(harness));

        await Task.Delay(TimeSpan.FromSeconds(6), ct);

        Assert.Equal(1, harness.Server.GetBoundsSnapshot().Peers);
        Assert.Equal(1, harness.Server.GetServiceSnapshot().StreamsActive);
        Assert.True(harness.Server.GetServiceSnapshot().LongestInactivity >= TimeSpan.FromSeconds(5.5));
        await cancel.CancelAsync();
        await ServiceHarness.WaitUntilAsync(() => harness.Server.GetBoundsSnapshot().Peers == 0, "the streaming connection to close once idle", ct);
    }

    // ---- helpers ----

    private static async Task StreamBesideDataCallsAsync(TimeSpan duration, TimeSpan heartbeat, bool checkServiceIdle, CancellationToken ct)
    {
        await using var harness = await ServiceHarness.StartOsAsync(
            builder => builder.RegisterStream(ServiceProbe.Subscribe, new LocalRpcStreamProfile { HeartbeatInterval = heartbeat }),
            ct);
        await using var channel = harness.NewChannel();
        await using var idleChannel = harness.NewChannel();
        var client = new ServiceClient(channel.CallInvoker);
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var watch = Stopwatch.StartNew();
        if (checkServiceIdle)
        {
            _ = await new ServiceClient(idleChannel.CallInvoker).Work(-1, 0, cancellation: ct).ResponseAsync.WaitAsync(ServiceHarness.Patience, ct);
        }

        // The stream: the owner's heartbeat every interval; the client records every arrival.
        using var subscription = client.Subscribe(ServiceProbeService.SubscribeRequest(0, SubscribeMode.Heartbeat, (int)heartbeat.TotalMilliseconds), cancellation: stop.Token);
        var arrivals = new List<TimeSpan>();
        var reader = Task.Run(
            async () =>
            {
                try
                {
                    while (await subscription.ResponseStream.MoveNext(stop.Token))
                    {
                        lock (arrivals)
                        {
                            arrivals.Add(watch.Elapsed);
                        }
                    }
                }
                catch (RpcException) when (stop.IsCancellationRequested)
                {
                    // The test ended the stream.
                }
                catch (OperationCanceledException) when (stop.IsCancellationRequested)
                {
                    // The test ended the stream.
                }
            },
            CancellationToken.None);

        // Sixteen data calls at a time on the same connection, for the whole run.
        long calls = 0, failures = 0, slowestTicks = 0;
        var loops = Enumerable.Range(0, 16).Select(loop => Task.Run(
            async () =>
            {
                var id = loop * 1_000_000;
                while (watch.Elapsed < duration)
                {
                    var started = Stopwatch.GetTimestamp();
                    try
                    {
                        _ = await client.Work(++id, 100, DateTime.UtcNow + TimeSpan.FromSeconds(30), ct).ResponseAsync;
                        Interlocked.Increment(ref calls);
                    }
                    catch (RpcException)
                    {
                        Interlocked.Increment(ref failures);
                    }

                    var elapsed = Stopwatch.GetElapsedTime(started).Ticks;
                    long seen;
                    while (elapsed > (seen = Interlocked.Read(ref slowestTicks)) && Interlocked.CompareExchange(ref slowestTicks, elapsed, seen) != seen)
                    {
                    }
                }
            },
            CancellationToken.None)).ToArray();

        // Samples once a second: the stream stays open on one connection and the library's inactivity stays within the heartbeat.
        var longestInactivity = TimeSpan.Zero;
        var peakDataActive = 0;
        int? peersAtNineMinutes = null;
        int? peersAfterIdleClose = null;
        while (watch.Elapsed < duration)
        {
            await Task.Delay(TimeSpan.FromSeconds(1), ct);
            var service = harness.Server.GetServiceSnapshot();
            var bounds = harness.Server.GetBoundsSnapshot();
            Assert.Equal(1, service.StreamsActive);
            longestInactivity = service.LongestInactivity > longestInactivity ? service.LongestInactivity : longestInactivity;
            peakDataActive = Math.Max(peakDataActive, bounds.DataActive);
            if (checkServiceIdle && peersAtNineMinutes is null && watch.Elapsed >= TimeSpan.FromMinutes(9))
            {
                peersAtNineMinutes = bounds.Peers;
            }

            if (checkServiceIdle && peersAfterIdleClose is null && watch.Elapsed >= TimeSpan.FromMinutes(10.5))
            {
                peersAfterIdleClose = bounds.Peers;
            }
        }

        await Task.WhenAll(loops).WaitAsync(TimeSpan.FromMinutes(1), ct);
        var admittedBeforeEnd = harness.Server.GetServiceSnapshot().PeersAdmitted;
        await stop.CancelAsync();
        await reader.WaitAsync(ServiceHarness.Patience, ct);
        await ServiceHarness.WaitUntilAsync(() => harness.Server.GetServiceSnapshot().StreamsActive == 0, "the stream to end", ct);

        List<TimeSpan> seenArrivals;
        lock (arrivals)
        {
            seenArrivals = [.. arrivals];
        }

        var gaps = seenArrivals.Zip(seenArrivals.Skip(1), (first, second) => second - first).ToArray();
        var longestGap = gaps.Length == 0 ? TimeSpan.Zero : gaps.Max();
        var summary = string.Create(
            CultureInfo.InvariantCulture,
            $"AF-DP-01 stream run on {Environment.OSVersion}: duration {watch.Elapsed:c}, heartbeat {heartbeat:c}, heartbeats {seenArrivals.Count}, longest gap {longestGap:c}, longest library inactivity {longestInactivity:c}, data calls {Interlocked.Read(ref calls)}, failures {Interlocked.Read(ref failures)}, slowest {TimeSpan.FromTicks(Interlocked.Read(ref slowestTicks)):c}, peak data active {peakDataActive}, peers admitted {admittedBeforeEnd}, peers at 9 min {peersAtNineMinutes}, peers after 10.5 min {peersAfterIdleClose}");
        TestContext.Current.TestOutputHelper?.WriteLine(summary);
        if (Environment.GetEnvironmentVariable("ARCFORGES_LOCALRPC_EVIDENCE") is { Length: > 0 } evidence)
        {
            await File.AppendAllTextAsync(evidence, summary + Environment.NewLine, Encoding.UTF8, ct);
        }

        Assert.True(watch.Elapsed >= duration);
        Assert.InRange(seenArrivals.Count, (int)(duration / heartbeat) - 1, (int)(duration / heartbeat) + 3);
        Assert.InRange(longestGap, TimeSpan.Zero, heartbeat + TimeSpan.FromSeconds(2));
        Assert.InRange(longestInactivity, TimeSpan.Zero, heartbeat + TimeSpan.FromSeconds(2));
        Assert.Equal(0, Interlocked.Read(ref failures));
        Assert.True(Interlocked.Read(ref calls) >= (long)(16 * duration.TotalSeconds * 0.5), "the data lane kept serving 16 concurrent calls");
        Assert.InRange(TimeSpan.FromTicks(Interlocked.Read(ref slowestTicks)), TimeSpan.Zero, TimeSpan.FromSeconds(5));
        Assert.Equal(16, harness.Probe.PeakRunning);

        // One connection carried the stream and the data calls the whole time (and one more was opened only for the idle check).
        Assert.Equal(checkServiceIdle ? 2 : 1, admittedBeforeEnd);
        if (checkServiceIdle)
        {
            Assert.Equal(2, peersAtNineMinutes);
            Assert.Equal(1, peersAfterIdleClose);
        }
    }

    private static string Describe(ServiceHarness harness)
    {
        var bounds = harness.Server.GetBoundsSnapshot();
        var service = harness.Server.GetServiceSnapshot();
        return string.Create(
            CultureInfo.InvariantCulture,
            $"running {harness.Probe.Running}, peers {bounds.Peers}, data active {bounds.DataActive}, streams {service.StreamsActive}, admitted {service.PeersAdmitted}, denied {string.Join(",", service.PeersDenied.Select(pair => pair.Key + "=" + pair.Value))}, refused {string.Join(",", bounds.Refused.Where(pair => pair.Value > 0).Select(pair => pair.Key + "=" + pair.Value))}");
    }

    private static LocalRpcPeerResolution Query(int processId, LocalRpcAcceptMoment accepted) => OperatingSystem.IsWindows()
        ? LocalRpcOsPeerResolver.QueryWindowsProcess(processId, accepted)
        : LocalRpcOsPeerResolver.QueryLinuxProcess(processId, LocalRpcOsPeerResolver.CurrentEffectiveUid!.Value, accepted);

    private static Process StartHelper(string mode)
    {
        var host = Environment.ProcessPath ?? throw new InvalidOperationException("The test executable path is unknown.");
        var start = new ProcessStartInfo(host)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        start.Environment["DOTNET_STARTUP_HOOKS"] = Path.Combine(AppContext.BaseDirectory, "ArcForges.LocalRpc.Tests.dll");
        if (string.Equals(Path.GetFileNameWithoutExtension(host), "dotnet", StringComparison.OrdinalIgnoreCase))
        {
            start.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, "ArcForges.LocalRpc.Tests.dll"));
        }

        start.Environment[LaunchHelperProcess.Variable] = mode;
        return Process.Start(start) ?? throw new InvalidOperationException("The helper process did not start.");
    }

    private static IEnumerable<Exception> ExceptionChain(Exception exception)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            yield return current;
        }
    }

    [SupportedOSPlatform("windows")]
    private static PipeSecurity UserAndSystemOnly()
    {
        var user = WindowsIdentity.GetCurrent().User!;
        var security = new PipeSecurity();
        security.SetOwner(user);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new PipeAccessRule(user, LocalRpcWindowsNative.GenericReadWrite, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), LocalRpcWindowsNative.GenericReadWrite, AccessControlType.Allow));
        return security;
    }

    /// <summary>Connects to a local pipe through the SMB redirector (<c>\\127.0.0.1\pipe\name</c>); null when it connected, else the failure.</summary>
    [SupportedOSPlatform("windows")]
    private static async Task<Exception?> ConnectThroughRedirectorAsync(string name, CancellationToken ct)
    {
        try
        {
            await using var client = new NamedPipeClientStream("127.0.0.1", name, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Anonymous);
            await client.ConnectAsync(5000, ct);
            return null;
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or IOException or TimeoutException)
        {
            return exception;
        }
    }

    [SupportedOSPlatform("windows")]
    private static async Task AssertRedirectorOutcomeAsync(uint rejectFlag, PipeSecurity security, bool admitted, CancellationToken ct)
    {
        var name = "af-svc-flag-" + Guid.NewGuid().ToString("N");
        await using var pipe = LocalRpcWindowsNative.CreateServicePipe(name, first: true, rejectFlag, security);
        var waiting = pipe.WaitForConnectionAsync(ct);
        var failure = await ConnectThroughRedirectorAsync(name, ct);
        if (admitted)
        {
            Assert.Null(failure);
            await waiting.WaitAsync(ServiceHarness.Patience, ct);
        }
        else
        {
            Assert.IsType<UnauthorizedAccessException>(failure);
        }
    }
}
