// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// Explicit local opt-in checks of the wrong-user procedure helpers with real processes and real endpoints (set
/// ARCFORGES_LOCALRPC_OS_STREAMS=1; skipped by default and never run in hosted CI). Every serving route over every transport is
/// admitted for its own account and a refusal expected by that account is INVALID; a real access-denied answer of the operating
/// system is classified as a refusal; a self-owned pipe squatter passes the client's ownership check and a self-owned foreign root
/// is admitted. These prove that the helpers work. They are same-account controls and never wrong-user evidence.
/// </summary>
[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcWrongUserProcedureChecks
{
    private const string OptIn = "Explicit local process checks only (ARCFORGES_LOCALRPC_OS_STREAMS=1).";
    private const string WindowsOptIn = "Explicit local Windows process check only (ARCFORGES_LOCALRPC_OS_STREAMS=1 on Windows).";
    private const string LinuxOptIn = "Explicit local Linux process check only (ARCFORGES_LOCALRPC_OS_STREAMS=1 on Linux).";
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(60);

    public static bool Enabled => LocalRpcOsStreamChecks.Enabled;

    public static bool WindowsEnabled => Enabled && OperatingSystem.IsWindows();

    public static bool LinuxEnabled => Enabled && OperatingSystem.IsLinux();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public static TheoryData<string, string> RoutesAndTransports()
    {
        var data = new TheoryData<string, string>();
        foreach (var route in new[] { "plain", "launch", "registration" })
        {
            if (OperatingSystem.IsWindows())
            {
                data.Add(route, "named-pipe");
            }

            data.Add(route, "unix-socket");
        }

        return data;
    }

    [Theory(Skip = OptIn, SkipUnless = nameof(Enabled))]
    [MemberData(nameof(RoutesAndTransports))]
    public async Task EveryRouteIsAdmittedForItsOwnAccountAndARefusalExpectedByThatAccountIsInvalid(string route, string transport)
    {
        var identity = WrongUserIdentity.Current();
        using var server = StartHelper("wrong-user-serve|" + route + "|" + transport);
        var serving = (await ReadLineAsync(server)).Split('|');
        Assert.Equal(5, serving.Length);
        Assert.Equal("SERVING", serving[0]);
        Assert.Equal(transport, serving[1]);
        Assert.Equal(identity.Value, serving[3]);
        Assert.Equal(server.Id.ToString(System.Globalization.CultureInfo.InvariantCulture), serving[4]);
        var address = serving[2];
        var connect = "wrong-user-connect|" + transport + "|" + address + "|" + serving[3] + "|";

        var before = await RunToExitAsync(connect + "admitted-control");
        var refused = await RunToExitAsync(connect + "refused");
        var after = await RunToExitAsync(connect + "admitted-control");

        Assert.Equal((WrongUserHelperProcess.ExitMatch, "ADMITTED"), (before.Code, before.Lines[^1]));
        Assert.Equal("IDENTITY|" + identity.Value, before.Lines[0]);
        Assert.Equal((WrongUserHelperProcess.ExitInvalid, "INVALID|same-account"), (refused.Code, refused.Lines[^1]));
        Assert.Equal((WrongUserHelperProcess.ExitMatch, "ADMITTED"), (after.Code, after.Lines[^1]));

        await StopAsync(server);
        if (transport == "unix-socket")
        {
            Assert.False(File.Exists(address), "The serving helper removes its socket when it stops.");
        }

        var gone = await RunToExitAsync(connect + "admitted-control");
        Assert.Equal(WrongUserHelperProcess.ExitInconclusive, gone.Code);
        Assert.StartsWith("INCONCLUSIVE|", gone.Lines[^1], StringComparison.Ordinal);
    }

    [Fact(Skip = WindowsOptIn, SkipUnless = nameof(WindowsEnabled))]
    [SupportedOSPlatform("windows")]
    public async Task APipeThatGrantsOnlySystemIsRefusedByTheOperatingSystemAndClassifiedAsAccessDenied()
    {
        var name = "af-wu-system-" + Guid.NewGuid().ToString("N");
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        await using var pipe = NamedPipeServerStreamAcl.Create(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, security);
        var connect = "wrong-user-connect|named-pipe|" + name + "|" + WrongUserHelperProcess.SystemSid + "|";

        var refused = await RunToExitAsync(connect + "refused");
        var control = await RunToExitAsync(connect + "admitted-control");

        Assert.Equal((WrongUserHelperProcess.ExitMatch, "REFUSED|access-denied"), (refused.Code, refused.Lines[^1]));
        Assert.Equal((WrongUserHelperProcess.ExitMismatch, "REFUSED|access-denied"), (control.Code, control.Lines[^1]));
    }

    [Fact(Skip = LinuxOptIn, SkipUnless = nameof(LinuxEnabled))]
    [UnsupportedOSPlatform("windows")]
    public async Task ASocketInADirectoryWithNoPermissionsIsRefusedByTheKernelAndClassifiedAsAccessDenied()
    {
        if (WrongUserIdentity.Current().IsRoot)
        {
            Assert.Skip("Root bypasses discretionary access control, so no refusal can be observed.");
            return;
        }

        var directory = Directory.CreateTempSubdirectory("afwu-");
        try
        {
            var path = Path.Combine(directory.FullName, "s.sock");
            using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            listener.Bind(new UnixDomainSocketEndPoint(path));
            listener.Listen(4);
            var connect = "wrong-user-connect|unix-socket|" + path + "|0|";
            var open = await RunToExitAsync(connect + "admitted-control");
            Assert.Equal((WrongUserHelperProcess.ExitMatch, "ADMITTED"), (open.Code, open.Lines[^1]));

            File.SetUnixFileMode(directory.FullName, UnixFileMode.None);
            var refused = await RunToExitAsync(connect + "refused");

            Assert.Equal((WrongUserHelperProcess.ExitMatch, "REFUSED|access-denied"), (refused.Code, refused.Lines[^1]));
        }
        finally
        {
            File.SetUnixFileMode(directory.FullName, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            directory.Delete(recursive: true);
        }
    }

    [Fact(Skip = WindowsOptIn, SkipUnless = nameof(WindowsEnabled))]
    public async Task ASelfOwnedSquatterPassesTheClientOwnershipCheckAndARefusalExpectedByItsOwnerIsInvalid()
    {
        var name = "af-wu-squat-" + Guid.NewGuid().ToString("N");
        using var squatter = StartHelper("wrong-user-squat-pipe|" + name);
        var squatting = (await ReadLineAsync(squatter)).Split('|');
        Assert.Equal(["SQUATTING", name], squatting[..2]);
        Assert.Contains(squatting[2], WrongUserIdentity.Current().Principals);

        var raw = await RunToExitAsync("wrong-user-connect|named-pipe|" + name + "|" + squatting[2] + "|admitted-control");
        var passed = await RunToExitAsync("wrong-user-client|" + name + "|" + squatting[2] + "|admitted-control");
        var invalid = await RunToExitAsync("wrong-user-client|" + name + "|" + squatting[2] + "|refused");

        Assert.Equal((WrongUserHelperProcess.ExitMatch, "ADMITTED"), (raw.Code, raw.Lines[^1]));
        Assert.Equal((WrongUserHelperProcess.ExitMatch, "PASSED-OWNERSHIP"), (passed.Code, passed.Lines[^1]));
        Assert.Equal((WrongUserHelperProcess.ExitInvalid, "INVALID|same-account"), (invalid.Code, invalid.Lines[^1]));
        var stopped = await StopAsync(squatter);
        Assert.StartsWith("STOPPED|stop|accepted=", stopped, StringComparison.Ordinal);
    }

    [Fact(Skip = WindowsOptIn, SkipUnless = nameof(WindowsEnabled))]
    public async Task AForeignRootMadeForTheOwnSidIsAdmittedByTheLaunchAuthorityInAnotherProcess()
    {
        var parent = Directory.CreateTempSubdirectory("afwu-");
        try
        {
            var root = Path.Combine(parent.FullName, "rt");
            var user = WrongUserIdentity.Current().Value;

            var made = await RunToExitAsync("wrong-user-foreign-root-make|" + root + "|" + user);
            var admitted = await RunToExitAsync("wrong-user-root-check|" + root + "|admitted-control");
            var invalid = await RunToExitAsync("wrong-user-root-check|" + root + "|refused");

            Assert.Equal((WrongUserHelperProcess.ExitMatch, "FOREIGN-ROOT|" + root + "|" + user + "|" + user), (made.Code, made.Lines[^1]));
            Assert.Equal((WrongUserHelperProcess.ExitMatch, "ADMITTED"), (admitted.Code, admitted.Lines[^1]));
            Assert.Equal((WrongUserHelperProcess.ExitInvalid, "INVALID|same-account"), (invalid.Code, invalid.Lines[^1]));
        }
        finally
        {
            parent.Delete(recursive: true);
        }
    }

    private static Process StartHelper(string mode)
    {
        var host = Environment.ProcessPath ?? throw new InvalidOperationException("The test executable path is unknown.");
        var start = new ProcessStartInfo(host)
        {
            RedirectStandardInput = true,
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

    private static async Task<string> ReadLineAsync(Process process)
    {
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        bounded.CancelAfter(Patience);
        try
        {
            return await process.StandardOutput.ReadLineAsync(bounded.Token)
                ?? throw new InvalidOperationException("The helper closed its output: " + await process.StandardError.ReadToEndAsync(Ct));
        }
        catch (OperationCanceledException) when (!Ct.IsCancellationRequested)
        {
            throw new TimeoutException("The helper printed no line in time.");
        }
    }

    private static async Task<string> StopAsync(Process process)
    {
        await process.StandardInput.WriteLineAsync("STOP".AsMemory(), Ct);
        await process.StandardInput.FlushAsync(Ct);
        var stopped = await ReadLineAsync(process);
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        bounded.CancelAfter(Patience);
        await process.WaitForExitAsync(bounded.Token);
        Assert.Equal(WrongUserHelperProcess.ExitMatch, process.ExitCode);
        return stopped;
    }

    private static async Task<(int Code, string[] Lines)> RunToExitAsync(string mode)
    {
        using var process = StartHelper(mode);
        process.StandardInput.Close();
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        bounded.CancelAfter(Patience);
        var error = process.StandardError.ReadToEndAsync(bounded.Token);
        var output = await process.StandardOutput.ReadToEndAsync(bounded.Token);
        await process.WaitForExitAsync(bounded.Token);
        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        Assert.True(lines.Length > 0, "The helper printed nothing: " + await error);
        return (process.ExitCode, lines);
    }
}
