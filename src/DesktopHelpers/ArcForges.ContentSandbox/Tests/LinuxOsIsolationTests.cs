// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using ArcForges.ContentSandbox.Broker;
using ArcForges.ContentSandbox.Broker.Linux;
using ArcForges.ContentSandbox.Contracts;
using ArcForges.ContentSandbox.Host;
using ArcForges.ContentSandbox.HostileFixture;
using ArcForges.ContentSandbox.Native;
using Xunit;
using BrokerNative = ArcForges.ContentSandbox.Broker.Native.LinuxNative;
using HelperNative = ArcForges.ContentSandbox.Native.LinuxNative;

namespace ArcForges.ContentSandbox.Tests;

/// <summary>
/// The opt-in Linux operating-system checks: the real Linux launcher starts a published Native AOT hostile fixture, which applies the
/// helper's own Landlock, seccomp, no_new_privs and limit profile to itself and is then attacked from inside by a deliberately hostile
/// first-party script. They never run by default and never in hosted CI (P2-017). To run them once on a Linux machine (a native file system,
/// not a Windows mount): <c>dotnet publish src/DesktopHelpers/ArcForges.ContentSandbox/Fixture/ArcForges.ContentSandbox.HostileFixture.csproj
/// -c Release -r linux-x64</c>, then set <c>ARCFORGES_CONTENTSANDBOX_LINUX_OS=1</c> and <c>ARCFORGES_CONTENTSANDBOX_FIXTURE</c> to that
/// publish directory and run this test project. The first check records the kernel facts; the profile needs multithread Landlock (the TSYNC
/// flag of landlock_restrict_self), so on a kernel that refuses it the helper must refuse fail-closed, that refusal is checked, and the
/// containment set is skipped as "blocked on a Linux kernel with multithread Landlock (TSYNC), not proven". Every result is evidence only for the
/// machine, the kernel and the fixture that ran.
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxOsIsolationTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static void RequireOptIn() =>
        Assert.SkipUnless(
            LinuxOsHarness.IsEnabled,
            "Set ARCFORGES_CONTENTSANDBOX_LINUX_OS=1 and ARCFORGES_CONTENTSANDBOX_FIXTURE to a published linux-x64 hostile fixture on Linux (never in hosted CI).");

    /// <summary>The containment set needs a kernel that accepts multithread Landlock; anything else is blocked, never passed.</summary>
    private static LinuxKernelFacts RequireMultithreadLandlock()
    {
        RequireOptIn();
        var facts = LinuxOsHarness.Facts;
        Assert.SkipUnless(
            facts.TsyncAccepted,
            "blocked on a Linux kernel with multithread Landlock (TSYNC), not proven: landlock_restrict_self with the TSYNC flag answered "
                + facts.LandlockTsync.Describe() + " on kernel " + facts.Release + ".");
        return facts;
    }

    [Fact]
    public void TheKernelFactsAreRecorded()
    {
        RequireOptIn();
        var facts = LinuxOsHarness.Facts;
        LinuxOsHarness.Evidence("kernel facts", facts.Lines());

        Assert.False(string.IsNullOrWhiteSpace(facts.Release));
        Assert.True(facts.LandlockAbi >= 1 || facts.LandlockAbiError != 0, "the Landlock ABI query gave no answer");

        // Every restricting probe ran in its own child copy of this test host and answered; none of them restricted this process, which still
        // opens a file outside any helper allowlist.
        foreach (var answer in new[] { facts.LandlockThread, facts.LandlockTsync, facts.SeccompTsync, facts.CloseRange })
        {
            Assert.True(answer.Answered, answer.Name + " did not answer: " + answer.Describe());
        }

        Assert.Equal(0, LinuxOsHarness.OpenError("/etc/passwd"));

        // A kernel with Landlock accepts a single-thread restriction; the TSYNC answer is either success or a definite error number.
        if (facts.LandlockAbi >= 1)
        {
            Assert.Equal(0L, facts.LandlockThread.Result);
        }

        Assert.True(facts.LandlockTsync.Result == 0 || facts.LandlockTsync.Error > 0, facts.LandlockTsync.Describe());
    }

    [Fact]
    public async Task OnAKernelWithoutMultithreadLandlockTheHelperRefusesBeforeAnyParserRuns()
    {
        RequireOptIn();
        var facts = LinuxOsHarness.Facts;
        Assert.SkipWhen(facts.TsyncAccepted, "This kernel accepts multithread Landlock: the containment set applies instead of the refusal.");
        using var harness = LinuxOsHarness.Create();
        var before = LinuxOsHarness.FixtureChildren();
        await using var launcher = harness.NewLauncher();

        // The script would attack at open time: nothing of it may run, because the helper must refuse before it serves a call.
        var launched = await launcher.LaunchAsync(Fixtures.Script("image 8 8", "attack file /etc/hostname", "crash-on-open"), Ct);
        LinuxOsHarness.Evidence("fail-closed refusal", [launched.Failure?.Code ?? "success", launched.Detail ?? string.Empty]);

        Assert.False(launched.IsSuccess);
        Assert.Equal("security.isolation_unavailable", launched.Failure!.Code);
        var detail = launched.Detail ?? string.Empty;
        Assert.Contains(" exit=" + ContentSandboxContract.ExitIsolationUnavailable.ToString(CultureInfo.InvariantCulture), detail, StringComparison.Ordinal);
        Assert.Contains(LinuxProfileSteps.Refused(LinuxProfileSteps.LandlockTsync, facts.LandlockTsync.Error), detail, StringComparison.Ordinal);

        // The refusal is attributed to that one step: no later step and no self-check ran, and the helper is gone and reaped.
        Assert.DoesNotContain(LinuxProfileSteps.SeccompTsync, detail, StringComparison.Ordinal);
        Assert.DoesNotContain("was not denied", detail, StringComparison.Ordinal);
        Assert.Equal(before, LinuxOsHarness.FixtureChildren());
    }

    [Fact]
    public async Task AHelperThatIsNotThePinnedBuildIsNeverStarted()
    {
        RequireOptIn();
        using var harness = LinuxOsHarness.Create();
        var options = harness.Options() with { HelperSha256 = SHA256.HashData("another build"u8) };
        await using var launcher = new ContentSandboxLauncher(options);
        var before = LinuxOsHarness.FixtureChildren();
        var launched = await launcher.LaunchAsync(Fixtures.Script("image 8 8"), Ct);
        LinuxOsHarness.Evidence("integrity refusal", [launched.Failure?.Code ?? "success"]);
        Assert.Equal("resource.integrity_failed", launched.Failure!.Code);
        Assert.Equal(before, LinuxOsHarness.FixtureChildren());
    }

    [Fact]
    public void TheProductionSlotSealsRefuseShrinkingAndGrowing()
    {
        RequireOptIn();
        const int length = 64 * 1024;
        var descriptor = LinuxSealedMemory.Create(length, [], out var stream);
        using (stream)
        {
            var seals = BrokerNative.Fcntl(descriptor, LinuxOsHarness.FGetSeals, 0);
            Assert.Equal(BrokerNative.SealShrink | BrokerNative.SealGrow | BrokerNative.SealSeal, seals);

            // The kernel refuses both resizes with EPERM, and the seal of the seals means no further seal can be added (or any removed).
            var resize = LinuxAttacks.Resize(descriptor);
            Assert.Equal("resize:DENIED:shrink." + HelperNative.Eperm.ToString(CultureInfo.InvariantCulture) + ".grow." + HelperNative.Eperm.ToString(CultureInfo.InvariantCulture), resize);
            Assert.Equal(length, stream.Length);
            Assert.Equal(-1, BrokerNative.Fcntl(descriptor, BrokerNative.FAddSeals, LinuxOsHarness.FSealWrite));
            Assert.Equal(HelperNative.Eperm, Marshal.GetLastPInvokeError());

            // Writes stay possible (the helper writes tiles into a slot), and the read-only reopen the launcher hands over as the input cannot be
            // mapped writable even by an unconfined process: the input's protection is the descriptor, not the confinement.
            stream.Write([1, 2, 3]);
            stream.Flush();
            Assert.Equal("map-write:ALLOWED:mapped", LinuxAttacks.MapWritable(descriptor));
            using var readOnly = File.OpenHandle("/proc/self/fd/" + descriptor.ToString(CultureInfo.InvariantCulture), FileMode.Open, FileAccess.Read);
            var mapReadOnly = LinuxAttacks.MapWritable((int)readOnly.DangerousGetHandle());
            Assert.StartsWith("map-write:DENIED:", mapReadOnly, StringComparison.Ordinal);
            LinuxOsHarness.Evidence("production memfd seals", ["seals=0x" + seals.ToString("x", CultureInfo.InvariantCulture), resize, mapReadOnly]);
        }

        // Control: a file without the seals shrinks and grows, so the denial above is the seals and not a probe that cannot succeed.
        var path = Path.Combine(Path.GetTempPath(), "arcforges-cs-unsealed-" + Guid.NewGuid().ToString("N")[..8]);
        using var unsealed = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.DeleteOnClose);
        unsealed.SetLength(length);
        Assert.Equal("resize:ALLOWED:shrink+grow", LinuxAttacks.Resize((int)unsealed.SafeFileHandle.DangerousGetHandle()));
    }

    [Fact]
    public async Task TheHostileAttacksSucceedWhenUnconfinedSoTheirDenialsAreNotVacuous()
    {
        RequireOptIn();
        using var harness = LinuxOsHarness.Create();
        var planted = harness.PlantFile("product.db");
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port.ToString(CultureInfo.InvariantCulture);
        var accepted = listener.AcceptTcpClientAsync(Ct).AsTask();
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var udpPort = ((IPEndPoint)udp.Client.LocalEndPoint!).Port.ToString(CultureInfo.InvariantCulture);
        var received = udp.ReceiveAsync(Ct).AsTask();
        using var sibling = Process.Start(new ProcessStartInfo("/bin/sleep", "60") { UseShellExecute = false })!;
        try
        {
            var siblingId = sibling.Id.ToString(CultureInfo.InvariantCulture);
            var report = new[]
            {
                HostileAttacks.Run(["attack", "file", planted]),
                HostileAttacks.Run(["attack", "tcp", "127.0.0.1", port]),
                HostileAttacks.Run(["attack", "udp", "127.0.0.1", udpPort]),
                HostileAttacks.Run(["attack", "signal", siblingId]),
                HostileAttacks.Run(["attack", "proc-mem", siblingId]),
                HostileAttacks.Run(["attack", "spawn", "/bin/sh"]),
                HostileAttacks.Run(["attack", "open-threads", planted]),
                HostileAttacks.Run(["attack", "env"]),
            };
            LinuxOsHarness.Evidence("unconfined control report", report);

            Assert.StartsWith("file:ALLOWED:", report[0], StringComparison.Ordinal);
            Assert.Equal("tcp:ALLOWED:127.0.0.1", report[1]);
            Assert.StartsWith("udp:ALLOWED:", report[2], StringComparison.Ordinal);
            Assert.Equal("signal:ALLOWED:0", report[3]);
            Assert.Equal("proc-mem:ALLOWED:opened", report[4]);
            Assert.Equal("spawn:ALLOWED:started", report[5]);
            Assert.Equal("open-threads:ALLOWED:own+pool+new", report[6]);
            Assert.StartsWith("env:ALLOWED:", report[7], StringComparison.Ordinal);

            // The other side saw them too.
            using var client = await accepted.WaitAsync(TimeSpan.FromSeconds(10), Ct);
            Assert.Equal("arcforges", Encoding.ASCII.GetString((await received.WaitAsync(TimeSpan.FromSeconds(10), Ct)).Buffer));
        }
        finally
        {
            sibling.Kill();
            await sibling.WaitForExitAsync(Ct);
        }
    }

    [Fact]
    public async Task TheRealChildReadsAnImageThroughARestrictedProcessAndExitsCleanly()
    {
        _ = RequireMultithreadLandlock();
        using var harness = LinuxOsHarness.Create();
        await using var launcher = harness.NewLauncher();
        var launched = await launcher.LaunchAsync(Fixtures.Script("image 300 200"), Ct);
        Assert.True(launched.IsSuccess, launched.Failure?.Code + " " + launched.Detail);
        await using var invocation = launched.Value!;
        Assert.NotEqual(Environment.ProcessId, invocation.HelperProcess.ProcessId);
        var image = (await invocation.OpenImageAsync(0, 0, 1, Ct)).Value;
        using var tile = (await invocation.ReadImageTileAsync(image, 10, 20, 64, 32, Ct)).Value!;
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(tile.Bytes.Span)), tile.Sha256);
        Assert.Equal((byte)10, tile.Bytes.Span[0]);
        Assert.Equal((byte)20, tile.Bytes.Span[1]);
        await invocation.CloseAsync();
        Assert.Equal(ContentSandboxContract.ExitClean, await invocation.WaitForExitAsync(Ct));
    }

    [Fact]
    public async Task TheHostileChildCannotReadProductFilesReachTheNetworkTouchProcessesSpawnOrResizeItsSlots()
    {
        _ = RequireMultithreadLandlock();
        using var harness = LinuxOsHarness.Create();
        var productStore = harness.PlantFile("product.db");
        var tokenCache = harness.PlantFile("tokens.cache");
        using var listener = new TcpListener(IPAddress.Any, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port.ToString(CultureInfo.InvariantCulture);
        var tcpAccepted = listener.AcceptTcpClientAsync(Ct).AsTask();
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
        var udpPort = ((IPEndPoint)udp.Client.LocalEndPoint!).Port.ToString(CultureInfo.InvariantCulture);
        var udpReceived = udp.ReceiveAsync(Ct).AsTask();
        var lan = LinuxOsHarness.LanAddress();

        var options = harness.Options() with { Limits = new ContentSandboxLimits { TimeoutMs = 25000, MaxWidth = 4096, MaxHeight = 4096 } };
        await using var launcher = new ContentSandboxLauncher(options);
        await using var sibling = (await launcher.LaunchAsync(Fixtures.Script("image 8 8"), Ct)).Value!;
        var parentId = Environment.ProcessId.ToString(CultureInfo.InvariantCulture);
        var siblingId = sibling.HelperProcess.ProcessId.ToString(CultureInfo.InvariantCulture);
        var plan = LinuxLaunchPlan.TargetPlan(options.SlotCount);
        var input = plan.Single(item => item.Role == ContentSandboxHandleRole.Input).Target.ToString(CultureInfo.InvariantCulture);
        var lines = new List<string>
        {
            "image 32 32",
            "attack file " + productStore,
            "attack file " + tokenCache,
            "attack tcp 127.0.0.1 " + port,
            "attack udp 127.0.0.1 " + udpPort,
            "attack signal " + parentId,
            "attack signal " + siblingId,
            "attack proc-mem " + parentId,
            "attack proc-mem " + siblingId,
            "attack spawn /bin/sh",
            "attack map-write " + input,
            "attack open-threads " + productStore,
            "attack env",
        };
        if (lan is not null)
        {
            lines.Add("attack tcp " + lan + " " + port);
            lines.Add("attack udp " + lan + " " + udpPort);
        }

        var slots = plan.Where(item => item.Role >= ContentSandboxHandleRole.Slot0).ToList();
        lines.AddRange(slots.Select(item => "attack resize " + item.Target.ToString(CultureInfo.InvariantCulture)));
        var launched = await launcher.LaunchAsync(Fixtures.Script([.. lines]), Ct);
        Assert.True(launched.IsSuccess, launched.Failure?.Code + " " + launched.Detail);
        await using var attacker = launched.Value!;
        var opened = await attacker.OpenImageAsync(0, 0, 1, Ct);
        Assert.True(opened.IsSuccess, opened.Failure?.Code + " " + attacker.HelperDiagnostics);
        var report = (await attacker.GetImageInfoAsync(opened.Value, Ct)).Value!.Warnings.ToList();
        LinuxOsHarness.Evidence("attack report", report);

        var eperm = HelperNative.Eperm.ToString(CultureInfo.InvariantCulture);
        var eacces = HelperNative.Eacces.ToString(CultureInfo.InvariantCulture);
        Assert.Equal(["file:DENIED:UnauthorizedAccessException", "file:DENIED:UnauthorizedAccessException"], Lines(report, "file:"));
        Assert.All(Lines(report, "tcp:"), line => Assert.StartsWith("tcp:DENIED:", line, StringComparison.Ordinal));
        Assert.All(Lines(report, "udp:"), line => Assert.StartsWith("udp:DENIED:", line, StringComparison.Ordinal));
        Assert.Equal(["signal:DENIED:" + eperm, "signal:DENIED:" + eperm], Lines(report, "signal:"));
        Assert.All(Lines(report, "proc-mem:"), line => Assert.StartsWith("proc-mem:DENIED:", line, StringComparison.Ordinal));
        Assert.StartsWith("spawn:DENIED:", Assert.Single(Lines(report, "spawn:")), StringComparison.Ordinal);
        Assert.StartsWith("map-write:DENIED:", Assert.Single(Lines(report, "map-write:")), StringComparison.Ordinal);
        Assert.Equal(Enumerable.Repeat("resize:DENIED:shrink." + eperm + ".grow." + eperm, slots.Count), Lines(report, "resize:"));
        Assert.Equal("open-threads:DENIED:own." + eacces + ".pool." + eacces + ".new." + eacces, Assert.Single(Lines(report, "open-threads:")));
        Assert.Equal("env:DENIED:OnlySystemRoot", Assert.Single(Lines(report, "env:")));

        // What the child did not do is observed from the other side too: the listeners saw nothing and the planted files are unchanged.
        await Task.Delay(TimeSpan.FromSeconds(1), Ct);
        Assert.False(tcpAccepted.IsCompleted, "the child reached the TCP listener");
        Assert.False(udpReceived.IsCompleted, "the child delivered a datagram");
        Assert.Equal(harness.PlantedHash(productStore), Convert.ToHexStringLower(SHA256.HashData(await File.ReadAllBytesAsync(productStore, Ct))));
        await attacker.CloseAsync();
    }

    [Fact]
    public async Task TheRestrictedChildHoldsNoInternetSocket()
    {
        _ = RequireMultithreadLandlock();
        using var harness = LinuxOsHarness.Create();
        await using var launcher = harness.NewLauncher();
        await using var invocation = (await launcher.LaunchAsync(Fixtures.Script("image 8 8"), Ct)).Value!;
        var sockets = LinuxOsHarness.SocketInodes(invocation.HelperProcess.ProcessId);
        var internet = LinuxOsHarness.InternetSocketInodes();
        LinuxOsHarness.Evidence("helper sockets", [sockets.Count.ToString(CultureInfo.InvariantCulture) + " unix-or-other", string.Join(',', sockets.Intersect(internet))]);
        Assert.NotEmpty(sockets);
        Assert.Empty(sockets.Intersect(internet));
    }

    [Fact]
    public async Task ANativeCrashEndsOnlyTheHelperAndTheParentCarriesOnAndLaunchesAgain()
    {
        _ = RequireMultithreadLandlock();
        using var harness = LinuxOsHarness.Create();
        await using var launcher = harness.NewLauncher();
        await using (var invocation = (await launcher.LaunchAsync(Fixtures.Script("image 8 8", "crash-on-open"), Ct)).Value!)
        {
            var opened = await invocation.OpenImageAsync(0, 0, 1, Ct);
            Assert.Equal("resource.parser_failed", opened.Failure!.Code);
            var code = await invocation.WaitForExitAsync(Ct);
            Assert.NotEqual(0, code);
            LinuxOsHarness.Evidence("exit code after a native access violation", [code.ToString(CultureInfo.InvariantCulture)]);
        }

        await using var again = (await launcher.LaunchAsync(Fixtures.Script("image 8 8"), Ct)).Value!;
        Assert.True((await again.OpenImageAsync(0, 0, 1, Ct)).IsSuccess);
    }

    [Fact]
    public async Task AParserThatSpinsForeverIsTerminatedAtTheDeadlineAndItsProcessIsGone()
    {
        _ = RequireMultithreadLandlock();
        using var harness = LinuxOsHarness.Create();
        var options = harness.Options() with { Limits = new ContentSandboxLimits { TimeoutMs = 1500, MaxWidth = 4096, MaxHeight = 4096 } };
        await using var launcher = new ContentSandboxLauncher(options);
        await using var invocation = (await launcher.LaunchAsync(Fixtures.Script("image 64 64", "hang-on-tile"), Ct)).Value!;
        var image = (await invocation.OpenImageAsync(0, 0, 1, Ct)).Value;
        var watch = Stopwatch.StartNew();
        var tile = await invocation.ReadImageTileAsync(image, 0, 0, 8, 8, Ct);
        Assert.Equal("resource.parser_failed", tile.Failure!.Code);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(20), watch.Elapsed.ToString());
        _ = await invocation.WaitForExitAsync(Ct);
        Assert.Null(LinuxOsHarness.ProcessState(invocation.HelperProcess.ProcessId));
    }

    [Fact]
    public async Task MemoryExhaustionIsBoundedByTheDataLimitAndEndsOnlyTheHelper()
    {
        _ = RequireMultithreadLandlock();
        using var harness = LinuxOsHarness.Create();
        var options = harness.Options() with { Limits = new ContentSandboxLimits { MaxMemoryBytes = 256UL * 1024 * 1024, TimeoutMs = 20000, MaxWidth = 4096, MaxHeight = 4096 } };
        await using var launcher = new ContentSandboxLauncher(options);
        await using var invocation = (await launcher.LaunchAsync(Fixtures.Script("image 8 8", "oom-on-open"), Ct)).Value!;
        var opened = await invocation.OpenImageAsync(0, 0, 1, Ct);
        Assert.Equal("resource.parser_failed", opened.Failure!.Code);
        var code = await invocation.WaitForExitAsync(Ct);
        Assert.NotEqual(0, code);
        LinuxOsHarness.Evidence("exit code after exhausting the data limit", [code.ToString(CultureInfo.InvariantCulture)]);
        Assert.True(GC.GetTotalMemory(false) < 256L * 1024 * 1024 * 4);
    }

    [Fact]
    public async Task CancellationStopsASlowParserAndTheHelperAcknowledgesThroughTheControlSlot()
    {
        _ = RequireMultithreadLandlock();
        using var harness = LinuxOsHarness.Create();
        await using var launcher = harness.NewLauncher();
        await using var invocation = (await launcher.LaunchAsync(Fixtures.Script("image 64 64", "slow-on-tile 20000"), Ct)).Value!;
        var image = (await invocation.OpenImageAsync(0, 0, 1, Ct)).Value;
        using var source = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        var pending = invocation.ReadImageTileAsync(image, 0, 0, 8, 8, source.Token).AsTask();
        await Task.Delay(1000, Ct);
        var watch = Stopwatch.StartNew();
        await source.CancelAsync();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await pending);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(8), watch.Elapsed.ToString());
    }

    [Fact]
    public async Task ATileTheRestrictedParserOverrunsIsRefusedAndTheInvocationEnds()
    {
        _ = RequireMultithreadLandlock();
        using var harness = LinuxOsHarness.Create();
        await using var launcher = harness.NewLauncher();
        await using var invocation = (await launcher.LaunchAsync(Fixtures.Script("image 64 64", "overflow-on-tile"), Ct)).Value!;
        var image = (await invocation.OpenImageAsync(0, 0, 1, Ct)).Value;
        var tile = await invocation.ReadImageTileAsync(image, 0, 0, 16, 16, Ct);
        Assert.Equal("resource.parser_failed", tile.Failure!.Code);
        Assert.True(invocation.IsEnded);
    }

    [Fact]
    public async Task TheHelperDiesWithItsParent()
    {
        _ = RequireMultithreadLandlock();
        using var harness = LinuxOsHarness.Create();
        var info = LinuxOsHarness.TestHostStartInfo();
        info.RedirectStandardOutput = true;
        info.Environment[LinuxParentMode.Marker] = "1";
        info.Environment["ARCFORGES_CS_HELPER"] = harness.ExecutablePath;
        info.Environment["ARCFORGES_CS_ROOT"] = Fixtures.NewRoot();
        using var parent = Process.Start(info)!;
        var line = await parent.StandardOutput.ReadLineAsync(Ct) ?? string.Empty;
        Assert.StartsWith("HELPER ", line, StringComparison.Ordinal);
        var helperId = int.Parse(line["HELPER ".Length..], CultureInfo.InvariantCulture);
        Assert.NotNull(LinuxOsHarness.ProcessState(helperId));
        parent.Kill(entireProcessTree: false);
        await parent.WaitForExitAsync(Ct);
        var watch = Stopwatch.StartNew();
        while (LinuxOsHarness.ProcessState(helperId) is { } state && state != 'Z' && watch.Elapsed < TimeSpan.FromSeconds(15))
        {
            await Task.Delay(50, Ct);
        }

        var after = LinuxOsHarness.ProcessState(helperId);
        Assert.True(after is null or 'Z', "the helper outlived its killed parent");
        LinuxOsHarness.Evidence("helper outlived its killed parent", ["no"]);
    }

    private static List<string> Lines(IEnumerable<string> report, string prefix) =>
        report.Where(line => line.StartsWith(prefix, StringComparison.Ordinal)).ToList();
}

/// <summary>One restricting probe made by a child copy of the test host: its result, the error number and how the child ended.</summary>
/// <param name="Name">The probe.</param>
/// <param name="Result">The system call result (0 is success), or <see cref="long.MinValue"/> when the child gave no answer.</param>
/// <param name="Error">The error number when the call failed.</param>
/// <param name="Exit">The child's exit code.</param>
internal readonly record struct LinuxProbeAnswer(string Name, long Result, int Error, int Exit)
{
    internal bool Answered => Result != long.MinValue && Exit == 0;

    internal string Describe() =>
        !Answered ? "no answer (exit " + Exit.ToString(CultureInfo.InvariantCulture) + ")"
        : Result == 0 ? "0 (accepted)"
        : Result.ToString(CultureInfo.InvariantCulture) + " errno " + Error.ToString(CultureInfo.InvariantCulture);
}

/// <summary>What the kernel offers the Linux profile, recorded once per run.</summary>
internal sealed record LinuxKernelFacts(
    string Release,
    string Lsm,
    IReadOnlyList<string> Config,
    int LandlockAbi,
    int LandlockAbiError,
    LinuxProbeAnswer LandlockThread,
    LinuxProbeAnswer LandlockTsync,
    LinuxProbeAnswer SeccompTsync,
    LinuxProbeAnswer CloseRange,
    IReadOnlyList<string> Status,
    string MaxUserNamespaces,
    string PtraceScope)
{
    /// <summary>True when landlock_restrict_self accepts the TSYNC flag: the one condition the helper's profile cannot do without.</summary>
    internal bool TsyncAccepted => LandlockTsync.Answered && LandlockTsync.Result == 0;

    internal IEnumerable<string> Lines() =>
    [
        "release " + Release,
        "lsm " + Lsm,
        .. Config,
        "landlock_abi " + (LandlockAbi >= 1 ? LandlockAbi.ToString(CultureInfo.InvariantCulture) : "none errno " + LandlockAbiError.ToString(CultureInfo.InvariantCulture)),
        "landlock_restrict_self(flags=0) " + LandlockThread.Describe(),
        "landlock_restrict_self(TSYNC) " + LandlockTsync.Describe(),
        "seccomp(SET_MODE_FILTER, TSYNC) " + SeccompTsync.Describe(),
        "close_range(1000,1001,0) " + CloseRange.Describe(),
        .. Status,
        "max_user_namespaces " + MaxUserNamespaces,
        "yama ptrace_scope " + PtraceScope,
    ];
}

/// <summary>The machine side of the opt-in Linux checks: the published fixture, planted files and the kernel facts.</summary>
[SupportedOSPlatform("linux")]
internal sealed class LinuxOsHarness : IDisposable
{
    internal const int FGetSeals = 1034;
    internal const int FSealWrite = 0x8;
    private const string FixtureName = "ArcForges.ContentSandbox.HostileFixture";
    private static readonly char[] Whitespace = ['\t', ' '];
    private static readonly Lazy<LinuxKernelFacts> KernelFacts = new(ReadFacts, LazyThreadSafetyMode.ExecutionAndPublication);
    private readonly string _plantedDirectory;
    private readonly Dictionary<string, string> _hashes = [];

    private LinuxOsHarness(string executable, byte[] digest)
    {
        ExecutablePath = executable;
        Digest = digest;
        _plantedDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "arcforges-cs-os-" + Guid.NewGuid().ToString("N")[..8]);
    }

    internal static bool IsEnabled =>
        OperatingSystem.IsLinux()
        && Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true"
        && Environment.GetEnvironmentVariable("ARCFORGES_CONTENTSANDBOX_LINUX_OS") == "1"
        && Directory.Exists(Environment.GetEnvironmentVariable("ARCFORGES_CONTENTSANDBOX_FIXTURE"));

    /// <summary>The kernel facts, gathered once; the restricting probes run in child copies of the test host, never in this process.</summary>
    internal static LinuxKernelFacts Facts => KernelFacts.Value;

    /// <summary>The kernel's short name of a fixture process: the first 15 bytes of the executable name.</summary>
    internal static string FixtureCommand => FixtureName[..15];

    internal string ExecutablePath { get; }

    internal byte[] Digest { get; }

    /// <summary>The published fixture is used where it is: Landlock lets the helper read only its own directory, which is that one.</summary>
    internal static LinuxOsHarness Create()
    {
        var published = Path.GetFullPath(Environment.GetEnvironmentVariable("ARCFORGES_CONTENTSANDBOX_FIXTURE")!);
        var executable = Path.Combine(published, FixtureName);
        return new LinuxOsHarness(executable, SHA256.HashData(File.ReadAllBytes(executable)));
    }

    internal ContentSandboxLaunchOptions Options() => new()
    {
        HelperPath = ExecutablePath,
        HelperSha256 = Digest,
        ParserProfile = HostileProfile.ProfileId,
        RuntimeRoot = Fixtures.NewRoot(),
        Limits = new ContentSandboxLimits { TimeoutMs = 10000, MaxWidth = 4096, MaxHeight = 4096 },
        SlotCapacityBytes = 1024 * 1024,
        LaunchTimeout = TimeSpan.FromSeconds(60),
    };

    internal ContentSandboxLauncher NewLauncher() => new(Options());

    internal string PlantFile(string name)
    {
        _ = Directory.CreateDirectory(_plantedDirectory);
        var path = Path.Combine(_plantedDirectory, name);
        File.WriteAllText(path, "product secret " + name);
        _hashes[path] = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));
        return path;
    }

    internal string PlantedHash(string path) => _hashes[path];

    internal static string? LanAddress() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .Where(adapter => adapter.OperationalStatus == OperationalStatus.Up)
            .SelectMany(adapter => adapter.GetIPProperties().UnicastAddresses)
            .Select(address => address.Address)
            .Where(address => address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(address))
            .Select(address => address.ToString())
            .Order(StringComparer.Ordinal)
            .FirstOrDefault();

    /// <summary>A start of this test host as a child; when it runs under the <c>dotnet</c> host, the test assembly is named as its argument.</summary>
    internal static ProcessStartInfo TestHostStartInfo()
    {
        var path = Environment.ProcessPath!;
        var info = new ProcessStartInfo(path) { UseShellExecute = false };
        if (Path.GetFileNameWithoutExtension(path) == "dotnet")
        {
            info.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, typeof(LinuxOsHarness).Assembly.GetName().Name + ".dll"));
        }

        return info;
    }

    /// <summary>
    /// The fixture processes that are children of this process, live or not yet reaped. The short name is shared with this test host, so a live
    /// process also has to run the fixture executable; a process not yet reaped has no executable left to read and counts on its name.
    /// </summary>
    internal static int FixtureChildren()
    {
        var self = Environment.ProcessId.ToString(CultureInfo.InvariantCulture);
        return ProcessDirectories().Count(directory => ReadStat(directory) is { } stat && stat.Command == FixtureCommand && stat.Parent == self && RunsTheFixture(directory));
    }

    private static bool RunsTheFixture(string directory)
    {
        try
        {
            var target = new FileInfo(Path.Combine(directory, "exe")).LinkTarget;
            return target is null || Path.GetFileName(target) == FixtureName;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return true;
        }
    }

    /// <summary>The state letter of a process, or null when it no longer exists.</summary>
    internal static char? ProcessState(int processId) =>
        ReadStat("/proc/" + processId.ToString(CultureInfo.InvariantCulture)) is { } stat && stat.State.Length > 0 ? stat.State[0] : null;

    /// <summary>The socket inodes a process holds, from its descriptor table.</summary>
    internal static HashSet<string> SocketInodes(int processId)
    {
        var inodes = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in Directory.GetFiles("/proc/" + processId.ToString(CultureInfo.InvariantCulture) + "/fd").Order(StringComparer.Ordinal))
        {
            var target = new FileInfo(entry).LinkTarget;
            if (target is not null && target.StartsWith("socket:[", StringComparison.Ordinal))
            {
                _ = inodes.Add(target["socket:[".Length..^1]);
            }
        }

        return inodes;
    }

    /// <summary>Every TCP and UDP socket inode of this network namespace, listening or connected.</summary>
    internal static HashSet<string> InternetSocketInodes()
    {
        var inodes = new HashSet<string>(StringComparer.Ordinal);
        foreach (var table in new[] { "/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6" })
        {
            if (!File.Exists(table))
            {
                continue;
            }

            foreach (var row in File.ReadAllLines(table).Skip(1))
            {
                var fields = row.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (fields.Length > 9)
                {
                    _ = inodes.Add(fields[9]);
                }
            }
        }

        return inodes;
    }

    /// <summary>Opens a path read-only in this (unconfined) process; the error number, or 0 when it opened.</summary>
    internal static int OpenError(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            return 0;
        }
        catch (UnauthorizedAccessException)
        {
            return HelperNative.Eacces;
        }
        catch (IOException exception)
        {
            return exception.HResult & 0xFFFF;
        }
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_plantedDirectory))
            {
                Directory.Delete(_plantedDirectory, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // The planted files are under the user's own profile and harmless if a removal races.
        }
    }

    internal static void Evidence(string title, IEnumerable<string> lines)
    {
        var text = "[os-evidence] " + title + ": " + string.Join(" | ", lines);
        Console.Error.WriteLine(text);
        TestContext.Current.TestOutputHelper?.WriteLine(text);
    }

    private static IEnumerable<string> ProcessDirectories() =>
        Directory.GetDirectories("/proc")
            .Where(directory => Path.GetFileName(directory).All(char.IsAsciiDigit))
            .Order(StringComparer.Ordinal);

    private static (string Command, string State, string Parent)? ReadStat(string directory)
    {
        string text;
        try
        {
            text = File.ReadAllText(Path.Combine(directory, "stat"));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }

        var open = text.IndexOf('(', StringComparison.Ordinal);
        var close = text.LastIndexOf(')');
        if (open < 0 || close < open || close + 2 > text.Length)
        {
            return null;
        }

        var fields = text[(close + 2)..].Split(' ');
        return fields.Length < 2 ? null : (text[(open + 1)..close], fields[0], fields[1]);
    }

    private static LinuxKernelFacts ReadFacts()
    {
        var abi = (int)HelperNative.Syscall(LinuxKernelProbe.LandlockCreateRuleset, 0, 0, (nint)LandlockPlan.CreateRulesetVersion, 0, 0);
        var abiError = abi < 0 ? Marshal.GetLastPInvokeError() : 0;
        return new LinuxKernelFacts(
            ReadText("/proc/sys/kernel/osrelease"),
            ReadText("/sys/kernel/security/lsm"),
            ReadConfig(),
            abi,
            abiError,
            RunProbe(LinuxKernelProbe.LandlockThread),
            RunProbe(LinuxKernelProbe.LandlockTsync),
            RunProbe(LinuxKernelProbe.SeccompTsync),
            RunProbe(LinuxKernelProbe.CloseRange),
            File.ReadAllLines("/proc/self/status").Where(line => line.StartsWith("Seccomp", StringComparison.Ordinal) || line.StartsWith("NoNewPrivs", StringComparison.Ordinal))
                .Select(line => "self " + string.Join(' ', line.Split(Whitespace, StringSplitOptions.RemoveEmptyEntries)))
                .ToList(),
            ReadText("/proc/sys/user/max_user_namespaces"),
            ReadText("/proc/sys/kernel/yama/ptrace_scope"));
    }

    private static string ReadText(string path)
    {
        try
        {
            var text = File.ReadAllText(path).Trim();
            return text.Length == 0 ? "empty" : text;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return "absent (" + exception.GetType().Name + ")";
        }
    }

    /// <summary>The kernel build options that decide the profile, from <c>/proc/config.gz</c> when the kernel exposes it.</summary>
    private static List<string> ReadConfig()
    {
        string[] names = ["CONFIG_LSM", "CONFIG_SECURITY_LANDLOCK", "CONFIG_SECCOMP_FILTER", "CONFIG_USER_NS"];
        try
        {
            using var file = File.OpenRead("/proc/config.gz");
            using var gzip = new GZipStream(file, CompressionMode.Decompress);
            using var reader = new StreamReader(gzip, Encoding.ASCII);
            var found = new Dictionary<string, string>(StringComparer.Ordinal);
            while (reader.ReadLine() is { } line)
            {
                foreach (var name in names)
                {
                    if (line.StartsWith(name + "=", StringComparison.Ordinal) || line == "# " + name + " is not set")
                    {
                        found[name] = line;
                    }
                }
            }

            return [.. names.Select(name => found.TryGetValue(name, out var line) ? line : name + " absent")];
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return ["/proc/config.gz absent (" + exception.GetType().Name + ")"];
        }
    }

    /// <summary>Runs one restricting probe in a child copy of this test host and reads its one answer line.</summary>
    private static LinuxProbeAnswer RunProbe(string name)
    {
        var info = TestHostStartInfo();
        info.RedirectStandardOutput = true;
        info.Environment[LinuxKernelProbe.Marker] = name;
        using var child = Process.Start(info)!;
        var output = child.StandardOutput.ReadToEndAsync();
        if (!child.WaitForExit(TimeSpan.FromSeconds(60)))
        {
            child.Kill();
            child.WaitForExit();
            return new LinuxProbeAnswer(name, long.MinValue, 0, -1);
        }

        var line = output.GetAwaiter().GetResult().Split('\n').FirstOrDefault(text => text.StartsWith("PROBE " + name + " ", StringComparison.Ordinal));
        var parts = line?.Split(' ');
        return parts is { Length: 4 }
            && long.TryParse(parts[2], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var result)
            && int.TryParse(parts[3], NumberStyles.None, CultureInfo.InvariantCulture, out var error)
            ? new LinuxProbeAnswer(name, result, error, child.ExitCode)
            : new LinuxProbeAnswer(name, long.MinValue, 0, child.ExitCode);
    }
}

/// <summary>
/// The restricting kernel probes. Each one changes the process that makes it (no_new_privs, a Landlock domain or a seccomp filter), so it runs
/// only in a child copy of the test host started with the marker variable, which writes one answer line and exits before any test runs.
/// </summary>
[SupportedOSPlatform("linux")]
internal static class LinuxKernelProbe
{
    internal const string Marker = "ARCFORGES_CS_LINUX_PROBE";
    internal const string LandlockThread = "landlock-thread";
    internal const string LandlockTsync = "landlock-tsync";
    internal const string SeccompTsync = "seccomp-tsync";
    internal const string CloseRange = "close-range";
    internal const int LandlockCreateRuleset = 444;
    private const int LandlockRestrictSelf = 446;
    private const int LandlockRestrictSelfTsync = 1 << 3;
    private const int SeccompSetModeFilter = 1;
    private const int SeccompFilterFlagTsync = 1;
    private const int CloseRangeCall = 436;

    [ModuleInitializer]
    internal static void RunWhenAProbe()
    {
        var probe = Environment.GetEnvironmentVariable(Marker);
        if (string.IsNullOrEmpty(probe) || !OperatingSystem.IsLinux())
        {
            return;
        }

        // A restricted thread can no longer read files, and the runtime loads assemblies lazily (the console stack among them), so after the probe
        // the answer is written and the process ended with raw system calls only; number formatting is warmed up before.
        _ = long.MinValue.ToString(CultureInfo.InvariantCulture);
        var (result, error) = Run(probe);
        WriteAndExit("PROBE " + probe + " " + result.ToString(CultureInfo.InvariantCulture) + " " + error.ToString(CultureInfo.InvariantCulture) + "\n");
    }

    private static unsafe void WriteAndExit(string line)
    {
        var x64 = SeccompProgram.Current == LinuxArchitecture.X64;
        var bytes = Encoding.ASCII.GetBytes(line);
        fixed (byte* text = bytes)
        {
            _ = HelperNative.Syscall(x64 ? 1 : 64, 1, (nint)text, bytes.Length, 0, 0);
        }

        _ = HelperNative.Syscall(x64 ? 231 : 94, 0, 0, 0, 0, 0);
    }

    private static (long Result, int Error) Run(string probe) => probe switch
    {
        LandlockThread => RestrictSelf(0),
        LandlockTsync => RestrictSelf(LandlockRestrictSelfTsync),
        SeccompTsync => AllowEverythingOnEveryThread(),
        CloseRange => Answer(HelperNative.Syscall(CloseRangeCall, 1000, 1001, 0, 0, 0)),
        _ => (long.MinValue, 0),
    };

    private static (long Result, int Error) Answer(nint result) => (result, result == 0 ? 0 : Marshal.GetLastPInvokeError());

    /// <summary>no_new_privs, a ruleset that handles only file reads, then landlock_restrict_self with the given flags.</summary>
    private static unsafe (long Result, int Error) RestrictSelf(int flags)
    {
        if (HelperNative.Prctl(HelperNative.PrSetNoNewPrivs, 1, 0, 0, 0) != 0)
        {
            return (-2, Marshal.GetLastPInvokeError());
        }

        var attribute = stackalloc ulong[1];
        attribute[0] = LandlockPlan.ReadFile;
        var ruleset = HelperNative.Syscall(LandlockCreateRuleset, (nint)attribute, 8, 0, 0, 0);
        if (ruleset < 0)
        {
            return (-3, Marshal.GetLastPInvokeError());
        }

        return Answer(HelperNative.Syscall(LandlockRestrictSelf, ruleset, flags, 0, 0, 0));
    }

    /// <summary>no_new_privs, then a seccomp filter that allows every call, synchronised to every thread of the runtime.</summary>
    private static unsafe (long Result, int Error) AllowEverythingOnEveryThread()
    {
        var architecture = SeccompProgram.Current;
        if (architecture == LinuxArchitecture.Unsupported || HelperNative.Prctl(HelperNative.PrSetNoNewPrivs, 1, 0, 0, 0) != 0)
        {
            return (-2, Marshal.GetLastPInvokeError());
        }

        var bytes = SeccompProgram.Serialize([new BpfInstruction(0x06, 0, 0, SeccompProgram.RetAllow)]);
        fixed (byte* filter = bytes)
        {
            var program = stackalloc byte[16];
            *(ushort*)program = (ushort)(bytes.Length / 8);
            *(nint*)(program + 8) = (nint)filter;
            return Answer(HelperNative.Syscall(SeccompProgram.SeccompCall(architecture), SeccompSetModeFilter, SeccompFilterFlagTsync, (nint)program, 0, 0));
        }
    }
}

/// <summary>
/// Lets the test assembly act as the launching parent of a real Linux helper for the parent-death check: when the marker variable is set, the
/// assembly launches the helper, reports its process id and waits to be killed.
/// </summary>
[SupportedOSPlatform("linux")]
internal static class LinuxParentMode
{
    internal const string Marker = "ARCFORGES_CS_LINUX_PARENT_MODE";

    [ModuleInitializer]
    internal static void RunWhenAParent()
    {
        if (Environment.GetEnvironmentVariable(Marker) != "1" || !OperatingSystem.IsLinux())
        {
            return;
        }

        var executable = Environment.GetEnvironmentVariable("ARCFORGES_CS_HELPER")!;
        var options = new ContentSandboxLaunchOptions
        {
            HelperPath = executable,
            HelperSha256 = SHA256.HashData(File.ReadAllBytes(executable)),
            ParserProfile = HostileProfile.ProfileId,
            RuntimeRoot = Environment.GetEnvironmentVariable("ARCFORGES_CS_ROOT")!,
            SlotCapacityBytes = 1024 * 1024,
            LaunchTimeout = TimeSpan.FromSeconds(60),
        };
        var launcher = new ContentSandboxLauncher(options);
        var result = launcher.LaunchAsync(Encoding.UTF8.GetBytes("HOSTILE1\nimage 8 8\n")).AsTask().GetAwaiter().GetResult();
        if (!result.IsSuccess)
        {
            Console.Out.WriteLine("FAILED " + result.Failure!.Code + " " + result.Detail);
            Environment.Exit(3);
        }

        Console.Out.WriteLine("HELPER " + result.Value!.HelperProcess.ProcessId.ToString(CultureInfo.InvariantCulture));
        Console.Out.Flush();
        Thread.Sleep(Timeout.Infinite);
    }
}
