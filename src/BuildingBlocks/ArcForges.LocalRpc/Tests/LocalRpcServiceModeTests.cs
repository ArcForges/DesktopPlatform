// SPDX-License-Identifier: AGPL-3.0-only
using Grpc.Core;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// Service mode (AF-DP-01) offline: the configuration rules, the peer in the connection decision and in handlers, per-method deadlines, the
/// stream lane and its back-pressure, and the idle rules. These run in hosted CI over real Kestrel HTTP/2 and Grpc.Net.Client on in-memory
/// streams, with a fixed peer answer standing in for the OS (the OS peer, endpoint access and real-duration checks are
/// <see cref="LocalRpcServiceOsChecks"/>, opt-in).
/// </summary>
public sealed class LocalRpcServiceModeTests
{
    private static readonly LocalRpcStreamProfile Silent = new() { HeartbeatInterval = TimeSpan.FromSeconds(15) };

    private static FixedPeerResolver Admit() => new(() => LocalRpcPeerResolution.Of(FixedPeerResolver.CurrentProcess));

    // ---- configuration ----

    [Fact]
    public void ServiceDefaultsRaiseOnlyTheConnectionBoundAndTheIdleClose()
    {
        var service = LocalRpcLimits.ServiceDefaults;
        var ordinary = new LocalRpcLimits();

        Assert.Equal(ordinary with { MaxConnections = 64, IdleTimeout = TimeSpan.FromMinutes(10) }, service);
        Assert.Equal(TimeSpan.FromSeconds(10), service.HandshakeTimeout);
        Assert.Equal(8, service.MaxStreamCallsPerConnection);
        Assert.Equal(32, service.MaxStreamCallsPerProcess);
        Assert.Equal(16, service.MaxActiveCalls);
        Assert.Equal(64, service.MaxQueuedCalls);
        Assert.Equal(TimeSpan.FromSeconds(10), service.DefaultCallDeadline);
        Assert.Equal(TimeSpan.FromSeconds(30), service.MaxCallDeadline);
        Assert.Equal(8, ordinary.MaxConnections);
        Assert.Equal(TimeSpan.FromSeconds(60), ordinary.IdleTimeout);

        _ = (service with { MaxConnections = 256 }).Validated(LocalRpcServerMode.Service);
        _ = (service with { MaxConnections = 1 }).Validated(LocalRpcServerMode.Service);
        Assert.Throws<ArgumentOutOfRangeException>(() => (service with { MaxConnections = 257 }).Validated(LocalRpcServerMode.Service));
        Assert.Throws<ArgumentOutOfRangeException>(() => (service with { MaxConnections = 0 }).Validated(LocalRpcServerMode.Service));
        Assert.Throws<ArgumentOutOfRangeException>(() => (service with { MaxConnections = 65 }).Validated(LocalRpcServerMode.ParentChild));
        Assert.Throws<ArgumentOutOfRangeException>(() => (service with { MaxConnections = 65 }).Validated());
        Assert.Throws<ArgumentOutOfRangeException>(() => (service with { MaxStreamCallsPerConnection = 9 }).Validated(LocalRpcServerMode.Service));
        Assert.Throws<ArgumentOutOfRangeException>(() => (service with { MaxStreamCallsPerConnection = 0 }).Validated(LocalRpcServerMode.Service));
        Assert.Throws<ArgumentOutOfRangeException>(() => (service with { MaxStreamCallsPerProcess = 257 }).Validated(LocalRpcServerMode.Service));
        Assert.Throws<ArgumentOutOfRangeException>(() => (service with { MaxStreamCallsPerProcess = 0 }).Validated(LocalRpcServerMode.Service));
        Assert.Throws<ArgumentOutOfRangeException>(() => (service with { IdleTimeout = TimeSpan.FromMinutes(11) }).Validated(LocalRpcServerMode.Service));
        Assert.Throws<ArgumentOutOfRangeException>(() => (service with { MaxCallDeadline = TimeSpan.FromSeconds(31) }).Validated(LocalRpcServerMode.Service));
    }

    [Fact]
    public void TheDefaultServerIsParentChildAndHasNoStreamLaneAndNoRaisedDeadline()
    {
        Assert.Equal(LocalRpcServerMode.ParentChild, new LocalRpcServerOptions().Mode);
        Assert.Equal(LocalRpcServerMode.ParentChild, LocalRpcServer.CreateBuilder(new LocalRpcStreamSupplier()).Options.Mode);

        var streaming = LocalRpcServer.CreateBuilder(new LocalRpcStreamSupplier()).AddService(new ServiceProbeService())
            .RegisterStream(ServiceProbe.Subscribe, Silent);
        Assert.Contains("service-mode lane", Assert.Throws<InvalidOperationException>(streaming.Build).Message, StringComparison.Ordinal);

        var raised = LocalRpcServer.CreateBuilder(new LocalRpcStreamSupplier()).AddService(new ServiceProbeService())
            .RegisterMethod(ServiceProbe.Work, new LocalRpcCallProfile(TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60)));
        Assert.Contains("only lower", Assert.Throws<InvalidOperationException>(raised.Build).Message, StringComparison.Ordinal);

        var lowered = LocalRpcServer.CreateBuilder(new LocalRpcStreamSupplier()).AddService(new ServiceProbeService())
            .RegisterMethod(ServiceProbe.Work, new LocalRpcCallProfile(TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(5)));
        _ = lowered.Build();
        Assert.Throws<ArgumentNullException>(() => LocalRpcServer.CreateBuilder(new LocalRpcStreamSupplier()).Options = null!);
    }

    [Fact]
    public void AServiceListensOnlyOnItsOwnPlatformEndpointAndServesNoChildRegistration()
    {
        var supplied = LocalRpcServer.CreateBuilder(new LocalRpcStreamSupplier()).AddService(new ServiceProbeService());
        supplied.Options = new LocalRpcServerOptions { Mode = LocalRpcServerMode.Service };
        Assert.Contains("well-known endpoint", Assert.Throws<InvalidOperationException>(supplied.Build).Message, StringComparison.Ordinal);

        var foreignTransport = OperatingSystem.IsWindows()
            ? LocalRpcEndpoint.CreateForVerification(LocalRpcTransport.UnixDomainSocket, Path.Combine(Path.GetTempPath(), "af-svc.sock"))
            : LocalRpcEndpoint.CreateForVerification(LocalRpcTransport.NamedPipe, "af-svc-foreign");
        var foreign = LocalRpcServer.CreateBuilder(foreignTransport).AddService(new ServiceProbeService());
        foreign.Options = new LocalRpcServerOptions { Mode = LocalRpcServerMode.Service };
        Assert.Throws<PlatformNotSupportedException>(foreign.Build);

        var unknown = LocalRpcServer.CreateBuilder(new LocalRpcStreamSupplier()).AddService(new ServiceProbeService()).UsePeerResolver(Admit());
        unknown.Options = new LocalRpcServerOptions { Mode = (LocalRpcServerMode)7 };
        Assert.Throws<InvalidOperationException>(unknown.Build);
    }

    [Fact]
    public void AServiceServesNoChildRegistration()
    {
        using var world = new RegWorld();
        var session = world.Start();
        var builder = LocalRpcServer.CreateBuilder(new LocalRpcStreamSupplier()).AddService(new ServiceProbeService()).UsePeerResolver(Admit())
            .RequireRegistration(session.Registration);
        builder.Options = new LocalRpcServerOptions { Mode = LocalRpcServerMode.Service };

        Assert.Contains("no child registration", Assert.Throws<InvalidOperationException>(builder.Build).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ProfilesAreValidatedAndEveryMethodHasOneLane()
    {
        LocalRpcServerBuilder Builder() => LocalRpcServer.CreateBuilder(new LocalRpcStreamSupplier()).AddService(new ServiceProbeService());
        var second = TimeSpan.FromSeconds(1);

        Assert.Throws<ArgumentOutOfRangeException>(() => Builder().RegisterMethod(ServiceProbe.Work, new LocalRpcCallProfile(TimeSpan.Zero, second)));
        Assert.Throws<ArgumentOutOfRangeException>(() => Builder().RegisterMethod(ServiceProbe.Work, new LocalRpcCallProfile(2 * second, second)));
        Assert.Throws<ArgumentOutOfRangeException>(() => Builder().RegisterMethod(ServiceProbe.Work, new LocalRpcCallProfile(second, TimeSpan.FromSeconds(121))));
        _ = Builder().RegisterMethod(ServiceProbe.Work, new LocalRpcCallProfile(second, LocalRpcCallProfile.LongestServiceDeadline));
        Assert.Throws<ArgumentNullException>(() => Builder().RegisterMethod(ServiceProbe.Work, null!));
        Assert.Throws<ArgumentNullException>(() => Builder().RegisterMethod(null!, new LocalRpcCallProfile(second, second)));
        Assert.Throws<ArgumentException>(() => Builder().RegisterMethod("not a service", "Work", new LocalRpcCallProfile(second, second)));
        Assert.Throws<ArgumentException>(() => Builder().RegisterStream(ServiceProbe.Work, Silent));
        Assert.Throws<ArgumentNullException>(() => Builder().RegisterStream((IMethod)null!, Silent));

        Assert.Throws<InvalidOperationException>(() => Builder()
            .RegisterMethod(ServiceProbe.Work, new LocalRpcCallProfile(second, second))
            .RegisterMethod(ServiceProbe.Work, new LocalRpcCallProfile(second, second)));
        Assert.Throws<InvalidOperationException>(() => Builder()
            .RegisterControl(LocalRpcControlOperation.Health, ServiceProbe.Work)
            .RegisterMethod(ServiceProbe.Work, new LocalRpcCallProfile(second, second)));
        Assert.Throws<InvalidOperationException>(() => Builder()
            .RegisterStream(ServiceProbe.Subscribe, Silent)
            .RegisterMethod(ServiceProbe.Subscribe, new LocalRpcCallProfile(second, second)));
        Assert.Throws<InvalidOperationException>(() => Builder()
            .RegisterMethod(ServiceProbe.Work, new LocalRpcCallProfile(second, second))
            .RegisterControl(LocalRpcControlOperation.Health, ServiceProbe.Work));
        Assert.Throws<InvalidOperationException>(() => Builder()
            .RegisterStream(ServiceProbe.Subscribe, Silent)
            .RegisterStream(ServiceProbe.Subscribe, Silent));

        Assert.Throws<ArgumentOutOfRangeException>(() => Builder().RegisterStream(ServiceProbe.Subscribe, Silent with { MaxLifetime = TimeSpan.Zero }));
        Assert.Throws<ArgumentOutOfRangeException>(() => Builder().RegisterStream(ServiceProbe.Subscribe, Silent with { HeartbeatInterval = TimeSpan.Zero }));
        Assert.Throws<ArgumentOutOfRangeException>(() => Builder().RegisterStream(ServiceProbe.Subscribe, Silent with { HeartbeatInterval = TimeSpan.FromMinutes(11) }));
        Assert.Throws<ArgumentOutOfRangeException>(() => Builder().RegisterStream(ServiceProbe.Subscribe, Silent with { MaxBufferedMessages = 0 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => Builder().RegisterStream(ServiceProbe.Subscribe, Silent with { MaxBufferedMessages = 65_537 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => Builder().RegisterStream(ServiceProbe.Subscribe, Silent with { RequireReads = TimeSpan.Zero }));
        Assert.Equal(2048, new LocalRpcStreamProfile().MaxBufferedMessages);
        Assert.Equal(TimeSpan.FromSeconds(15), new LocalRpcStreamProfile().HeartbeatInterval);
        Assert.Null(new LocalRpcStreamProfile().MaxLifetime);
        Assert.Null(new LocalRpcStreamProfile().RequireReads);
    }

    [Fact]
    public async Task StartFailsWhenALaneMethodIsNotServedOrAStreamMethodIsNotServerStreaming()
    {
        var ct = TestContext.Current.CancellationToken;
        var unary = LocalRpcServer.CreateBuilder(new LocalRpcStreamSupplier()).AddService(new ServiceProbeService()).UsePeerResolver(Admit())
            .RegisterStream(ServiceProbe.ServiceName, "Work", Silent);
        unary.Options = new LocalRpcServerOptions { Mode = LocalRpcServerMode.Service };
        await using (var server = unary.Build())
        {
            var failure = await Assert.ThrowsAsync<InvalidOperationException>(() => server.StartAsync(ct));
            Assert.Contains("not a server-streaming method", failure.Message, StringComparison.Ordinal);
        }

        var unserved = LocalRpcServer.CreateBuilder(new LocalRpcStreamSupplier()).AddService(new ServiceProbeService()).UsePeerResolver(Admit())
            .RegisterMethod("arcforges.test.service.v1.Missing", "Work", new LocalRpcCallProfile(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1)));
        unserved.Options = new LocalRpcServerOptions { Mode = LocalRpcServerMode.Service };
        await using (var server = unserved.Build())
        {
            var failure = await Assert.ThrowsAsync<InvalidOperationException>(() => server.StartAsync(ct));
            Assert.Contains("arcforges.test.service.v1.Missing/Work", failure.Message, StringComparison.Ordinal);
        }
    }

    // ---- peer identity ----

    [Fact]
    public async Task TheConnectionDecisionAndEveryHandlerOfTheConnectionSeeTheResolvedPeer()
    {
        var ct = TestContext.Current.CancellationToken;
        var resolver = Admit();
        LocalRpcConnectionInfo? decided = null;
        await using var harness = await ServiceHarness.StartOfflineAsync(
            resolver,
            builder => builder.AuthorizeConnections(connection =>
            {
                decided = connection;
                return true;
            }),
            cancellationToken: ct);
        await using var channel = harness.NewChannel();
        var client = new ServiceClient(channel.CallInvoker);

        _ = await client.WhoAmI(1).ResponseAsync.WaitAsync(ServiceHarness.Patience, ct);
        _ = await client.WhoAmI(2).ResponseAsync.WaitAsync(ServiceHarness.Patience, ct);

        Assert.Equal(1, resolver.Calls);
        Assert.Same(FixedPeerResolver.CurrentProcess, decided!.Peer);
        Assert.Same(FixedPeerResolver.CurrentProcess, harness.Probe.Peers[1]);
        Assert.Same(FixedPeerResolver.CurrentProcess, harness.Probe.Peers[2]);
        var snapshot = harness.Server.GetServiceSnapshot();
        Assert.Equal(1, snapshot.PeersAdmitted);
        Assert.All(snapshot.PeersDenied.Values, count => Assert.Equal(0, count));
        Assert.Equal(Enum.GetValues<LocalRpcPeerDenial>().Where(denial => denial != LocalRpcPeerDenial.None).Order(), snapshot.PeersDenied.Keys.Order());
    }

    [Theory]
    [InlineData(LocalRpcPeerDenial.ProcessExited)]
    [InlineData(LocalRpcPeerDenial.OtherUser)]
    [InlineData(LocalRpcPeerDenial.Unresolved)]
    public async Task APeerThatIsGoneUnresolvedOrOfAnotherUserIsDroppedBeforeTheOwnerDecides(LocalRpcPeerDenial denial)
    {
        var ct = TestContext.Current.CancellationToken;
        var decisions = 0;
        await using var harness = await ServiceHarness.StartOfflineAsync(
            new FixedPeerResolver(() => LocalRpcPeerResolution.Deny(denial)),
            builder => builder.AuthorizeConnections(_ =>
            {
                Interlocked.Increment(ref decisions);
                return true;
            }),
            cancellationToken: ct);
        await using var channel = harness.NewChannel();

        var failure = await ServiceClient.FailureAsync(new ServiceClient(channel.CallInvoker).WhoAmI(1).ResponseAsync);

        Assert.Equal(StatusCode.Unavailable, failure.StatusCode);
        Assert.Equal(0, Volatile.Read(ref decisions));
        Assert.Empty(harness.Probe.Peers);
        await ServiceHarness.WaitUntilAsync(() => harness.Server.GetServiceSnapshot().PeersDenied[denial] >= 1, "the denial count", ct);
        Assert.Equal(0, harness.Server.GetServiceSnapshot().PeersAdmitted);
    }

    [Fact]
    public async Task TheOwnersRefusalOfAResolvedPeerIsCountedAsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await ServiceHarness.StartOfflineAsync(
            Admit(),
            builder => builder.AuthorizeConnectionsAsync((connection, _) => ValueTask.FromResult(connection.Peer is null)),
            cancellationToken: ct);
        await using var channel = harness.NewChannel();

        var failure = await ServiceClient.FailureAsync(new ServiceClient(channel.CallInvoker).WhoAmI(1).ResponseAsync);

        Assert.Equal(StatusCode.Unavailable, failure.StatusCode);
        await ServiceHarness.WaitUntilAsync(() => harness.Server.GetServiceSnapshot().PeersDenied[LocalRpcPeerDenial.Refused] >= 1, "the refusal count", ct);
    }

    [Fact]
    public async Task AParentChildServerReadsNoPeerAndHasNoServiceActivity()
    {
        var ct = TestContext.Current.CancellationToken;
        var supplier = new LocalRpcStreamSupplier();
        var probe = new ServiceProbeService();
        LocalRpcConnectionInfo? decided = null;
        await using var server = LocalRpcServer.CreateBuilder(supplier).AddService(probe).AuthorizeConnections(connection =>
        {
            decided = connection;
            return true;
        }).Build();
        await server.StartAsync(ct);
        await using var channel = LocalRpcClientChannel.CreateFromStreams(_ =>
        {
            var (client, end) = InMemoryDuplexStream.CreatePair();
            Assert.True(supplier.TrySupply(end));
            return ValueTask.FromResult<Stream>(client);
        });

        var answer = await new ServiceClient(channel.CallInvoker).WhoAmI(1).ResponseAsync.WaitAsync(ServiceHarness.Patience, ct);

        Assert.Equal("none"u8.ToArray(), answer);
        Assert.Null(probe.Peers[1]);
        Assert.Null(decided!.Peer);
        var snapshot = server.GetServiceSnapshot();
        Assert.Equal(0, snapshot.PeersAdmitted + snapshot.StreamsActive + snapshot.StreamsAdmitted);
    }

    [Fact]
    public async Task AHandlerOfAMethodThatIsNotInTheStreamLaneHasNoStreamWriter()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await ServiceHarness.StartOfflineAsync(Admit(), cancellationToken: ct);
        await using var channel = harness.NewChannel();
        using var call = new ServiceClient(channel.CallInvoker).Subscribe(ServiceProbeService.SubscribeRequest(1, SubscribeMode.Silent), DateTime.UtcNow + ServiceHarness.Patience, ct);

        var (_, failure) = await ServiceClient.DrainAsync(call, ct);

        // Without RegisterStream the method is an ordinary data call: OpenLocalRpcStream refuses and the handler fails.
        Assert.Equal(StatusCode.Unknown, failure!.StatusCode);
        Assert.Equal(0, harness.Server.GetServiceSnapshot().StreamsAdmitted);
    }

    // ---- per-method deadlines ----

    [Fact]
    public async Task AProfiledMethodGetsItsDeadlinesAndUnprofiledMethodsKeepTheDataDeadlines()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await ServiceHarness.StartOfflineAsync(
            Admit(),
            builder => builder
                .RegisterMethod(ServiceProbe.Work, new LocalRpcCallProfile(TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60)))
                .RegisterMethod(ServiceProbe.Wait, new LocalRpcCallProfile(TimeSpan.FromMilliseconds(300), TimeSpan.FromMilliseconds(600))),
            cancellationToken: ct);
        await using var channel = harness.NewChannel();
        var client = new ServiceClient(channel.CallInvoker);

        _ = await client.Work(1, 0, cancellation: ct).ResponseAsync.WaitAsync(ServiceHarness.Patience, ct);
        _ = await client.Work(2, 0, DateTime.UtcNow + TimeSpan.FromSeconds(90), ct).ResponseAsync.WaitAsync(ServiceHarness.Patience, ct);
        _ = await client.Work(3, 0, DateTime.UtcNow + TimeSpan.FromSeconds(20), ct).ResponseAsync.WaitAsync(ServiceHarness.Patience, ct);
        _ = await client.WhoAmI(4).ResponseAsync.WaitAsync(ServiceHarness.Patience, ct);
        using (var feed = client.Feed(5, DateTime.UtcNow + TimeSpan.FromSeconds(45), ct))
        {
            Assert.True(await feed.ResponseStream.MoveNext(ct));
        }

        var waited = System.Diagnostics.Stopwatch.StartNew();
        var expired = await ServiceClient.FailureAsync(client.Wait(6, cancellation: ct).ResponseAsync);
        var waitedFor = waited.Elapsed;
        var clamped = await ServiceClient.FailureAsync(client.Wait(7, DateTime.UtcNow + TimeSpan.FromSeconds(10), ct).ResponseAsync);

        var remaining = harness.Probe.RemainingAtStart;
        Assert.InRange(remaining[1], TimeSpan.FromSeconds(55), TimeSpan.FromSeconds(60.5));
        Assert.InRange(remaining[2], TimeSpan.FromSeconds(55), TimeSpan.FromSeconds(60.5));
        Assert.InRange(remaining[3], TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(20.5));
        Assert.InRange(remaining[4], TimeSpan.FromSeconds(25), TimeSpan.FromSeconds(30.5));
        Assert.InRange(remaining[5], TimeSpan.FromSeconds(25), TimeSpan.FromSeconds(30.5));
        Assert.InRange(remaining[6], TimeSpan.Zero, TimeSpan.FromMilliseconds(350));
        Assert.InRange(remaining[7], TimeSpan.Zero, TimeSpan.FromMilliseconds(650));
        Assert.Equal(StatusCode.DeadlineExceeded, expired.StatusCode);
        Assert.Equal(StatusCode.DeadlineExceeded, clamped.StatusCode);
        Assert.InRange(waitedFor, TimeSpan.FromMilliseconds(250), TimeSpan.FromSeconds(10));
    }

    [Fact]
    public async Task AnUnprofiledCallWithoutADeadlineGetsTheTenSecondDefault()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await ServiceHarness.StartOfflineAsync(Admit(), cancellationToken: ct);
        await using var channel = harness.NewChannel();

        _ = await new ServiceClient(channel.CallInvoker).Work(1, 0, cancellation: ct).ResponseAsync.WaitAsync(ServiceHarness.Patience, ct);

        Assert.InRange(harness.Probe.RemainingAtStart[1], TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10.5));
    }

    // ---- stream lane ----

    [Fact]
    public async Task TheStreamLaneHoldsEightStreamsPerConnectionBesideSixteenDataCallsAndRefusesTheNinthAtOnce()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await ServiceHarness.StartOfflineAsync(Admit(), builder => builder.RegisterStream(ServiceProbe.Subscribe, Silent), cancellationToken: ct);
        await using var channel = harness.NewChannel();
        var client = new ServiceClient(channel.CallInvoker);
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(ct);

        var streams = Enumerable.Range(1, 8).Select(id => client.Subscribe(ServiceProbeService.SubscribeRequest(id, SubscribeMode.Silent), cancellation: cancel.Token)).ToArray();
        await ServiceHarness.WaitUntilAsync(() => harness.Server.GetServiceSnapshot().StreamsActive == 8, "eight open streams", ct);
        var data = Enumerable.Range(100, 16).Select(id => client.Work(id, -1, DateTime.UtcNow + ServiceHarness.Patience, ct)).ToArray();
        await ServiceHarness.WaitUntilAsync(() => harness.Probe.Running == 16, "sixteen running data calls", ct);

        using var ninth = client.Subscribe(ServiceProbeService.SubscribeRequest(9, SubscribeMode.Silent), cancellation: ct);
        var (_, refused) = await ServiceClient.DrainAsync(ninth, ct);

        Assert.Equal(StatusCode.ResourceExhausted, refused!.StatusCode);
        Assert.True(LocalRpcRefusal.TryRead(refused, out var refusal));
        Assert.Equal(LocalRpcRefusalReason.StreamLaneFull, refusal!.Reason);
        Assert.Equal(16, harness.Server.GetBoundsSnapshot().DataActive);
        Assert.Equal(8, harness.Server.GetServiceSnapshot().StreamsActive);
        Assert.Equal(1, harness.Server.GetBoundsSnapshot().Refused[LocalRpcRefusalReason.StreamLaneFull]);
        Assert.False(harness.Probe.Writers.ContainsKey(9));

        harness.Probe.Gate.SetResult();
        await Task.WhenAll(data.Select(call => call.ResponseAsync)).WaitAsync(ServiceHarness.Patience, ct);
        await cancel.CancelAsync();
        foreach (var stream in streams)
        {
            stream.Dispose();
        }

        await ServiceHarness.WaitUntilAsync(() => harness.Server.GetServiceSnapshot().StreamsActive == 0, "the streams to end", ct);
        Assert.Equal(8, harness.Server.GetServiceSnapshot().StreamsEnded[LocalRpcStreamEndReason.Cancelled]);
    }

    [Fact]
    public async Task OneClientProcessHoldsAtMostThirtyTwoStreamsOverAllItsConnections()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await ServiceHarness.StartOfflineAsync(Admit(), builder => builder.RegisterStream(ServiceProbe.Subscribe, Silent), cancellationToken: ct);
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var channels = Enumerable.Range(0, 5).Select(_ => harness.NewChannel()).ToArray();
        try
        {
            var calls = channels.SelectMany((channel, index) => Enumerable.Range(0, 8).Select(slot =>
                new ServiceClient(channel.CallInvoker).Subscribe(ServiceProbeService.SubscribeRequest((index * 8) + slot, SubscribeMode.Silent), cancellation: cancel.Token))).ToArray();
            await ServiceHarness.WaitUntilAsync(
                () => harness.Server.GetServiceSnapshot().StreamsActive + harness.Server.GetBoundsSnapshot().Refused[LocalRpcRefusalReason.StreamLaneFull] == 40,
                "every stream to be admitted or refused",
                ct);

            Assert.Equal(32, harness.Server.GetServiceSnapshot().StreamsActive);
            Assert.Equal(8, harness.Server.GetBoundsSnapshot().Refused[LocalRpcRefusalReason.StreamLaneFull]);
            Assert.Equal(5, harness.Server.GetBoundsSnapshot().Peers);
            await cancel.CancelAsync();
            foreach (var call in calls)
            {
                call.Dispose();
            }

            await ServiceHarness.WaitUntilAsync(() => harness.Server.GetServiceSnapshot().StreamsActive == 0, "the streams to end", ct);
        }
        finally
        {
            foreach (var channel in channels)
            {
                await channel.DisposeAsync();
            }
        }
    }

    [Fact]
    public async Task AStreamIsExemptFromTheDataDeadlineCapAndHeldToItsProfile()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await ServiceHarness.StartOfflineAsync(
            Admit(),
            builder => builder.RegisterStream(ServiceProbe.Subscribe, Silent).RegisterStream(ServiceProbe.Feed, Silent with { MaxLifetime = TimeSpan.FromMinutes(60) }),
            cancellationToken: ct);
        await using var channel = harness.NewChannel();
        var client = new ServiceClient(channel.CallInvoker);
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(ct);

        using var unbounded = client.Subscribe(ServiceProbeService.SubscribeRequest(1, SubscribeMode.Silent), cancellation: cancel.Token);
        using var lifetime = client.Feed(2, cancellation: cancel.Token);
        using var clientShorter = client.Feed(3, DateTime.UtcNow + TimeSpan.FromMinutes(5), cancel.Token);
        using var clientLonger = client.Feed(4, DateTime.UtcNow + TimeSpan.FromHours(2), cancel.Token);
        await ServiceHarness.WaitUntilAsync(() => harness.Probe.RemainingAtStart.Count == 4, "four open streams", ct);

        Assert.Equal(TimeSpan.MaxValue, harness.Probe.RemainingAtStart[1]);
        Assert.InRange(harness.Probe.RemainingAtStart[2], TimeSpan.FromMinutes(59), TimeSpan.FromMinutes(60.1));
        Assert.InRange(harness.Probe.RemainingAtStart[3], TimeSpan.FromMinutes(4.5), TimeSpan.FromMinutes(5.1));
        Assert.InRange(harness.Probe.RemainingAtStart[4], TimeSpan.FromMinutes(59), TimeSpan.FromMinutes(60.1));
        await cancel.CancelAsync();
    }

    [Fact]
    public async Task AStreamWhoseLifetimeEndsIsAnsweredDeadlineExceeded()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await ServiceHarness.StartOfflineAsync(
            Admit(),
            builder => builder.RegisterStream(ServiceProbe.Subscribe, Silent with { MaxLifetime = TimeSpan.FromMilliseconds(400) }),
            cancellationToken: ct);
        await using var channel = harness.NewChannel();
        using var call = new ServiceClient(channel.CallInvoker).Subscribe(ServiceProbeService.SubscribeRequest(1, SubscribeMode.Heartbeat, 50), cancellation: ct);

        var (messages, failure) = await ServiceClient.DrainAsync(call, ct);

        Assert.Equal(StatusCode.DeadlineExceeded, failure!.StatusCode);
        Assert.True(messages >= 1);
        await ServiceHarness.WaitUntilAsync(() => harness.Server.GetServiceSnapshot().StreamsActive == 0, "the stream to end", ct);
        Assert.Equal(LocalRpcStreamEndReason.LifetimeEnded, harness.Probe.Writers[1].EndReason);
        Assert.Equal(1, harness.Server.GetServiceSnapshot().StreamsEnded[LocalRpcStreamEndReason.LifetimeEnded]);
    }

    [Fact]
    public async Task AClientThatReadsTooSlowlyOverflowsTheBufferAndGetsResourceExhaustedThenSubscribesAfresh()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await ServiceHarness.StartOfflineAsync(
            Admit(),
            builder => builder.RegisterStream(ServiceProbe.Subscribe, Silent with { MaxBufferedMessages = 8 }),
            cancellationToken: ct);
        await using var channel = harness.NewChannel();
        var client = new ServiceClient(channel.CallInvoker);
        using var burst = client.Subscribe(ServiceProbeService.SubscribeRequest(1, SubscribeMode.Burst, 1, count: 100_000, size: 16 * 1024), cancellation: ct);

        // The owner produces a message every millisecond or so; the client reads nothing until the server's writer has overflowed.
        await ServiceHarness.WaitUntilAsync(() => harness.Probe.Writers.TryGetValue(1, out var writer) && writer.EndReason != LocalRpcStreamEndReason.None, "the overflow", ct);
        Assert.Equal(LocalRpcStreamEndReason.Overflow, harness.Probe.Writers[1].EndReason);
        var (messages, failure) = await ServiceClient.DrainAsync(burst, ct);

        Assert.Equal(StatusCode.ResourceExhausted, failure!.StatusCode);
        Assert.True(LocalRpcStreamEnd.TryRead(failure, out var reason));
        Assert.Equal(LocalRpcStreamEndReason.Overflow, reason);
        Assert.False(LocalRpcRefusal.TryRead(failure, out _));
        Assert.InRange(messages, 1, 99_999);
        await ServiceHarness.WaitUntilAsync(() => harness.Server.GetServiceSnapshot().StreamsActive == 0, "the stream to end", ct);
        Assert.Equal(1, harness.Server.GetServiceSnapshot().StreamsEnded[LocalRpcStreamEndReason.Overflow]);

        using var fresh = client.Subscribe(ServiceProbeService.SubscribeRequest(2, SubscribeMode.Heartbeat, 20), cancellation: ct);
        Assert.True(await fresh.ResponseStream.MoveNext(ct));
        Assert.True(await fresh.ResponseStream.MoveNext(ct));
    }

    [Fact]
    public async Task AClientThatDoesNotReadWithinTheRequirementIsResetAndItsConnectionStillServesCalls()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await ServiceHarness.StartOfflineAsync(
            Admit(),
            builder => builder.RegisterStream(ServiceProbe.Subscribe, Silent with { MaxBufferedMessages = 65_536, RequireReads = TimeSpan.FromMilliseconds(500) }),
            cancellationToken: ct);
        await using var channel = harness.NewChannel();
        var client = new ServiceClient(channel.CallInvoker);
        using var stalled = client.Subscribe(ServiceProbeService.SubscribeRequest(1, SubscribeMode.Burst, count: 4096, size: 16 * 1024), cancellation: ct);

        await ServiceHarness.WaitUntilAsync(() => harness.Probe.Writers.TryGetValue(1, out var writer) && writer.EndReason != LocalRpcStreamEndReason.None, "the stalled reader to be detected", ct);

        Assert.Equal(LocalRpcStreamEndReason.ReadsStalled, harness.Probe.Writers[1].EndReason);
        var (_, failure) = await ServiceClient.DrainAsync(stalled, ct);
        Assert.NotNull(failure);
        Assert.NotEqual(StatusCode.OK, failure.StatusCode);
        _ = await client.Work(2, 0, cancellation: ct).ResponseAsync.WaitAsync(ServiceHarness.Patience, ct);
        await ServiceHarness.WaitUntilAsync(() => harness.Server.GetServiceSnapshot().StreamsEnded[LocalRpcStreamEndReason.ReadsStalled] == 1, "the stalled count", ct);
    }

    [Fact]
    public async Task TheLibraryMeasuresInactivityAndSendsNoHeartbeatOfItsOwn()
    {
        var ct = TestContext.Current.CancellationToken;
        var time = new ManualTimeProvider();
        await using var harness = await ServiceHarness.StartOfflineAsync(
            Admit(),
            builder => builder.RegisterStream(ServiceProbe.Subscribe, Silent with { HeartbeatInterval = TimeSpan.FromSeconds(15) }),
            time,
            ct);
        await using var channel = harness.NewChannel();
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(ct);
        using var silent = new ServiceClient(channel.CallInvoker).Subscribe(ServiceProbeService.SubscribeRequest(1, SubscribeMode.Silent), cancellation: cancel.Token);
        await ServiceHarness.WaitUntilAsync(() => harness.Probe.Writers.ContainsKey(1), "the stream to open", ct);
        var writer = harness.Probe.Writers[1];
        var next = silent.ResponseStream.MoveNext(cancel.Token);

        time.Advance(TimeSpan.FromSeconds(14));
        Assert.False(writer.HeartbeatOverdue);
        time.Advance(TimeSpan.FromSeconds(2));

        Assert.True(writer.HeartbeatOverdue);
        Assert.Equal(TimeSpan.FromSeconds(16), writer.Inactivity);
        Assert.Equal(TimeSpan.FromSeconds(16), harness.Server.GetServiceSnapshot().LongestInactivity);
        Assert.Equal(0, writer.Buffered);
        Assert.False(next.IsCompleted);

        Assert.True(writer.TryWrite(ServiceProbeService.Heartbeat(1)));
        Assert.True(await next.WaitAsync(ServiceHarness.Patience, ct));
        await ServiceHarness.WaitUntilAsync(() => writer.Inactivity == TimeSpan.Zero, "the message to reach the transport", ct);
        Assert.False(writer.HeartbeatOverdue);
        Assert.Throws<ArgumentNullException>(() => writer.TryWrite(null!));
        await cancel.CancelAsync();
    }

    // ---- idle rules ----

    [Fact]
    public async Task AServiceConnectionWithoutAnOpenStreamClosesAfterTenIdleMinutes()
    {
        var ct = TestContext.Current.CancellationToken;
        var time = new ManualTimeProvider();
        await using var harness = await ServiceHarness.StartOfflineAsync(Admit(), time: time, cancellationToken: ct);
        await using var channel = harness.NewChannel();
        _ = await new ServiceClient(channel.CallInvoker).Work(1, 0, DateTime.UtcNow + ServiceHarness.Patience, ct).ResponseAsync.WaitAsync(ServiceHarness.Patience, ct);
        await ServiceHarness.WaitUntilAsync(() => harness.Server.GetBoundsSnapshot().DataActive == 0, "the call to finish", ct);

        time.Advance(TimeSpan.FromMinutes(10) - TimeSpan.FromSeconds(1));
        await Task.Delay(100, ct);
        Assert.Equal(1, harness.Server.GetBoundsSnapshot().Peers);

        time.Advance(TimeSpan.FromSeconds(2));
        await ServiceHarness.WaitUntilAsync(() => harness.Server.GetBoundsSnapshot().Peers == 0, "the idle connection to close", ct);
    }

    [Fact]
    public async Task AConnectionHoldingAnOpenStreamIsNeverIdleAndTheIdleClockStartsWhenItEnds()
    {
        var ct = TestContext.Current.CancellationToken;
        var time = new ManualTimeProvider();
        await using var harness = await ServiceHarness.StartOfflineAsync(Admit(), builder => builder.RegisterStream(ServiceProbe.Subscribe, Silent), time, ct);
        await using var channel = harness.NewChannel();
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(ct);
        using var stream = new ServiceClient(channel.CallInvoker).Subscribe(ServiceProbeService.SubscribeRequest(1, SubscribeMode.Silent), cancellation: cancel.Token);
        await ServiceHarness.WaitUntilAsync(() => harness.Server.GetServiceSnapshot().StreamsActive == 1, "the stream to open", ct);

        for (var hour = 0; hour < 6; hour++)
        {
            time.Advance(TimeSpan.FromHours(1));
        }

        await Task.Delay(100, ct);
        Assert.Equal(1, harness.Server.GetBoundsSnapshot().Peers);
        Assert.Equal(1, harness.Server.GetServiceSnapshot().StreamsActive);
        Assert.Equal(TimeSpan.FromHours(6), harness.Server.GetServiceSnapshot().LongestInactivity);

        await cancel.CancelAsync();
        await ServiceHarness.WaitUntilAsync(() => harness.Server.GetServiceSnapshot().StreamsActive == 0, "the stream to end", ct);
        time.Advance(TimeSpan.FromMinutes(9));
        await Task.Delay(100, ct);
        Assert.Equal(1, harness.Server.GetBoundsSnapshot().Peers);
        time.Advance(TimeSpan.FromMinutes(1) + TimeSpan.FromSeconds(1));
        await ServiceHarness.WaitUntilAsync(() => harness.Server.GetBoundsSnapshot().Peers == 0, "the idle connection to close", ct);
    }

    [Fact]
    public async Task TheServiceHandshakeLimitStaysTenSeconds()
    {
        var ct = TestContext.Current.CancellationToken;
        var time = new ManualTimeProvider();
        var supplier = new LocalRpcStreamSupplier();
        var builder = LocalRpcServer.CreateBuilder(supplier).AddService(new ServiceProbeService()).UsePeerResolver(Admit()).UseTimeProvider(time);
        builder.Options = new LocalRpcServerOptions { Mode = LocalRpcServerMode.Service };
        await using var server = builder.Build();
        await server.StartAsync(ct);
        var (client, end) = InMemoryDuplexStream.CreatePair();
        await using var silentClient = client;
        Assert.True(supplier.TrySupply(end));
        await ServiceHarness.WaitUntilAsync(() => server.GetBoundsSnapshot().Peers == 1, "the connection to be accepted", ct);

        time.Advance(TimeSpan.FromSeconds(9));
        await Task.Delay(100, ct);
        Assert.Equal(1, server.GetBoundsSnapshot().Peers);
        time.Advance(TimeSpan.FromSeconds(2));
        await ServiceHarness.WaitUntilAsync(() => server.GetBoundsSnapshot().Peers == 0, "the silent connection to close", ct);
    }

    // ---- endpoint and stream-end parsing ----

    [Fact]
    public void TheWellKnownServiceEndpointIsPerUserAndValidated()
    {
        var hash = LocalRpcEndpoint.CurrentUserHash;
        Assert.Matches("^[0-9a-f]{32}$", hash);
        Assert.Equal(hash, LocalRpcEndpoint.CurrentUserHash);

        var endpoint = LocalRpcEndpoint.ForCurrentUserService("node", Path.Combine(Path.GetTempPath(), "af-run"));
        if (OperatingSystem.IsWindows())
        {
            Assert.Equal(LocalRpcTransport.NamedPipe, endpoint.Transport);
            Assert.Equal("arcforges-" + hash + "-node", endpoint.Address);
        }
        else
        {
            Assert.Equal(LocalRpcTransport.UnixDomainSocket, endpoint.Transport);
            var runtime = Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR");
            Assert.Equal(
                string.IsNullOrEmpty(runtime) ? Path.Combine(Path.GetTempPath(), "af-run", "node.sock") : Path.Combine(runtime, "arcforges", "node.sock"),
                endpoint.Address);
        }

        Assert.Equal(endpoint, LocalRpcEndpoint.ForCurrentUserService("node", Path.Combine(Path.GetTempPath(), "af-run")));
        Assert.NotEqual(endpoint, LocalRpcEndpoint.ForCurrentUserService("mcp", Path.Combine(Path.GetTempPath(), "af-run")));
        foreach (var invalid in new[] { string.Empty, "Node", "1node", "no_de", "node.x", new string('a', 33) })
        {
            Assert.Throws<ArgumentException>(() => LocalRpcEndpoint.ForCurrentUserService(invalid, Path.GetTempPath()));
        }

        Assert.Throws<ArgumentNullException>(() => LocalRpcEndpoint.ForCurrentUserService(null!));
    }

    [Fact]
    public void AStreamEndIsReadOnlyFromItsTrailer()
    {
        static RpcException Failure(Metadata trailers) => new(new Status(StatusCode.ResourceExhausted, string.Empty), trailers);
        foreach (var reason in Enum.GetValues<LocalRpcStreamEndReason>().Where(known => known != LocalRpcStreamEndReason.None))
        {
            Assert.True(LocalRpcStreamEnd.TryRead(Failure(new Metadata { { LocalRpcStreamEnd.Trailer, LocalRpcStreamEnd.NameOf(reason) } }), out var read));
            Assert.Equal(reason, read);
        }

        Assert.False(LocalRpcStreamEnd.TryRead(Failure([]), out var none));
        Assert.Equal(LocalRpcStreamEndReason.None, none);
        Assert.False(LocalRpcStreamEnd.TryRead(Failure(new Metadata { { LocalRpcStreamEnd.Trailer, "something-new" } }), out _));
        Assert.Throws<ArgumentNullException>(() => LocalRpcStreamEnd.TryRead(null!, out _));
        Assert.True(LocalRpcFailureClassifier.IsTransient(new LocalRpcRefusal(LocalRpcRefusalReason.StreamLaneFull)));
        Assert.Equal(StatusCode.ResourceExhausted, LocalRpcRefusal.StatusOf(LocalRpcRefusalReason.StreamLaneFull));
    }

    [Fact]
    public void TheLinuxProcReadersParseWhatTheKernelWrites()
    {
        Assert.Equal(1000u, LocalRpcLinuxProc.EffectiveUid("Name:\tx\nUid:\t1001\t1000\t1000\t1000\nGid:\t1\t1\t1\t1\n"));
        Assert.Null(LocalRpcLinuxProc.EffectiveUid("Name:\tx\n"));
        Assert.Null(LocalRpcLinuxProc.EffectiveUid("Uid:\t1\t2\n"));
        Assert.Equal(1234568L, LocalRpcLinuxProc.ParseUptimeTicks("12345.671 99.00\n"));
        Assert.Equal(1234567L, LocalRpcLinuxProc.ParseUptimeTicks("12345.67 99.00\n"));
        Assert.Null(LocalRpcLinuxProc.ParseUptimeTicks("x 1"));
        Assert.Null(LocalRpcLinuxProc.ParseUptimeTicks(string.Empty));
    }
}
