// SPDX-License-Identifier: AGPL-3.0-only
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Grpc.Core;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// Offline checks of the wrong-user procedure helpers (Tests/wrong-user-procedure.md): mode parsing, the outcome classification
/// tables, the exact owner-refusal match, the same-account and root guards, the exit codes and, on Windows, the foreign launch-root
/// access list. They run in hosted CI. None of them is wrong-user evidence: that needs a second account, which no check here has.
/// </summary>
public sealed class LocalRpcWrongUserProcedureTests
{
    private const string WindowsOnly = "Windows access control check.";
    private const string PipeOnly = "Windows Named Pipe check.";
    private const string OtherSid = "S-1-5-21-1000000001-1000000002-1000000003-1001";
    private static readonly WrongUserIdentity Owner = new("S-1-5-21-1-2-3-1000", ["S-1-5-21-1-2-3-1000"], IsRoot: false);
    private static readonly WrongUserIdentity Second = new(OtherSid, [OtherSid], IsRoot: false);
    private static readonly WrongUserIdentity Root = new("0", ["0"], IsRoot: true);

    public static bool IsWindows => OperatingSystem.IsWindows();

    private static string SocketPath => OperatingSystem.IsWindows() ? @"C:\afwu\c.sock" : "/tmp/afwu/c.sock";

    private static string RootPath => OperatingSystem.IsWindows() ? @"C:\afwu\rt" : "/tmp/afwu/rt";

    // ---- parsing ----

    [Fact]
    public void EveryModeParsesFromItsPipeSeparatedArguments()
    {
        Assert.Equal(new WrongUserServe(WrongUserRoute.Plain, WrongUserTransport.NamedPipe), Parse("wrong-user-serve|plain|named-pipe"));
        Assert.Equal(new WrongUserServe(WrongUserRoute.Launch, WrongUserTransport.UnixSocket), Parse("wrong-user-serve|launch|unix-socket"));
        Assert.Equal(new WrongUserServe(WrongUserRoute.Registration, WrongUserTransport.UnixSocket), Parse("wrong-user-serve|registration|unix-socket"));
        Assert.Equal(
            new WrongUserConnect(WrongUserTransport.NamedPipe, "afl-0123abcd", WrongUserHelperProcess.SystemSid, WrongUserExpectation.Refused),
            Parse("wrong-user-connect|named-pipe|afl-0123abcd|S-1-5-18|refused"));
        Assert.Equal(
            new WrongUserConnect(WrongUserTransport.UnixSocket, SocketPath, "1000", WrongUserExpectation.AdmittedControl),
            Parse("wrong-user-connect|unix-socket|" + SocketPath + "|1000|admitted-control"));
        Assert.Equal(new WrongUserSquatPipe("af-wu-squat"), Parse("wrong-user-squat-pipe|af-wu-squat"));
        Assert.Equal(new WrongUserClient("af-wu-squat", OtherSid, WrongUserExpectation.Refused), Parse("wrong-user-client|af-wu-squat|" + OtherSid + "|refused"));
        Assert.Equal(new WrongUserForeignRootMake(RootPath, OtherSid), Parse("wrong-user-foreign-root-make|" + RootPath + "|" + OtherSid));
        Assert.Equal(new WrongUserRootCheck(RootPath, WrongUserExpectation.AdmittedControl), Parse("wrong-user-root-check|" + RootPath + "|admitted-control"));
    }

    public static TheoryData<string> MalformedModes()
    {
        var root = OperatingSystem.IsWindows() ? @"C:\afwu\rt" : "/tmp/afwu/rt";
        return new()
        {
            string.Empty,
            "wrong-user-bogus|x",
            "serve|plain|named-pipe",
            "wrong-user-serve|plain",
            "wrong-user-serve|plain|named-pipe|extra",
            "wrong-user-serve|ftp|named-pipe",
            "wrong-user-serve|plain|tcp",
            "wrong-user-connect|named-pipe|bad name|S-1-5-18|refused",
            "wrong-user-connect|named-pipe|-starts-with-dash|S-1-5-18|refused",
            @"wrong-user-connect|named-pipe|\\.\pipe\x|S-1-5-18|refused",
            "wrong-user-connect|named-pipe|afl-x|S-1-5-18|maybe",
            "wrong-user-connect|named-pipe|afl-x|alice|refused",
            "wrong-user-connect|named-pipe|afl-x|S-1-|refused",
            "wrong-user-connect|named-pipe|afl-x|S-1-5--18|refused",
            "wrong-user-connect|named-pipe|afl-x|-1|refused",
            "wrong-user-connect|named-pipe|afl-x|12345678901|refused",
            "wrong-user-connect|unix-socket|relative/c.sock|1000|refused",
            "wrong-user-connect|named-pipe|afl-x|S-1-5-18",
            "wrong-user-squat-pipe|",
            "wrong-user-client|afl-x|S-1-5-18",
            "wrong-user-foreign-root-make|" + root + "|1000",
            "wrong-user-foreign-root-make|relative|S-1-5-18",
            "wrong-user-root-check|" + root + "|refused|extra",
            "wrong-user-root-check|" + root + Path.DirectorySeparatorChar + "|refused",
            "wrong-user-root-check|" + root + Path.DirectorySeparatorChar + ".." + Path.DirectorySeparatorChar + "rt|refused",
        };
    }

    [Theory]
    [MemberData(nameof(MalformedModes))]
    public async Task AMalformedModeIsAUsageErrorAndRunsNothing(string mode)
    {
        ArgumentNullException.ThrowIfNull(mode);
        Assert.Throws<FormatException>(() => Parse(mode));

        var (code, output, error) = await RunAsync(mode, Owner);

        Assert.Equal(WrongUserHelperProcess.ExitUsage, code);
        Assert.Empty(output);
        Assert.StartsWith("USAGE|", error, StringComparison.Ordinal);
    }

    // ---- classification ----

    private static readonly (Exception Failure, string Line)[] ConnectFailures =
    [
        (new UnauthorizedAccessException("Access to the path is denied."), "REFUSED|access-denied"),
        (new SocketException((int)SocketError.AccessDenied), "REFUSED|access-denied"),
        (new SocketException((int)SocketError.ConnectionRefused), "INCONCLUSIVE|refused"),
        (new SocketException((int)SocketError.AddressNotAvailable), "INCONCLUSIVE|not-found"),
        (new SocketException((int)SocketError.TimedOut), "INCONCLUSIVE|timeout"),
        (new SocketException((int)SocketError.NetworkDown), "INCONCLUSIVE|socket-NetworkDown"),
        (new TimeoutException(), "INCONCLUSIVE|timeout"),
        (new OperationCanceledException(), "INCONCLUSIVE|timeout"),
        (new TaskCanceledException(), "INCONCLUSIVE|timeout"),
        (new FileNotFoundException(), "INCONCLUSIVE|not-found"),
        (new DirectoryNotFoundException(), "INCONCLUSIVE|not-found"),
        (new IOException("All pipe instances are busy.", unchecked((int)0x800700E7)), "INCONCLUSIVE|busy"),
        (new IOException("The pipe has been ended."), "INCONCLUSIVE|io"),
        (new InvalidOperationException(), "INCONCLUSIVE|error-InvalidOperationException"),
    ];

    [Fact]
    public void OnlyAnAccessDeniedAnswerOfARawConnectIsARefusal()
    {
        Assert.All(ConnectFailures, row => Assert.Equal(row.Line, WrongUserHelperProcess.ClassifyConnectFailure(row.Failure).Line));
    }

    private static readonly (Exception Failure, string Line)[] ClientFailures =
    [
        (Wrapped(new LocalRpcConnectException("x", new UnauthorizedAccessException("Could not connect to the pipe because it was not owned by the current user."))), "REFUSED|not-owned-by-current-user"),
        (new LocalRpcConnectException("x", new UnauthorizedAccessException()), "REFUSED|not-owned-by-current-user"),
        (new AggregateException(new InvalidOperationException(), new HttpRequestException("h", new LocalRpcConnectException("x", new UnauthorizedAccessException()))), "REFUSED|not-owned-by-current-user"),
        (Wrapped(new LocalRpcConnectException("x", new TimeoutException())), "INCONCLUSIVE|connect-timeout"),
        (Wrapped(new LocalRpcConnectException("x", new IOException("outer", new UnauthorizedAccessException()))), "INCONCLUSIVE|connect-io"),
        (Wrapped(new LocalRpcConnectException("x")), "INCONCLUSIVE|connect-io"),
        (new RpcException(new Status(StatusCode.Unavailable, "closed", new IOException("The response ended prematurely."))), "PASSED-OWNERSHIP"),
        (new RpcException(new Status(StatusCode.Internal, "no debug exception")), "PASSED-OWNERSHIP"),
        (new UnauthorizedAccessException("not wrapped by the library's connect failure"), "PASSED-OWNERSHIP"),
    ];

    [Fact]
    public void AClientIsRefusedExactlyWhenTheLibraryConnectFailureWrapsAnAccessRefusal()
    {
        Assert.All(ClientFailures, row => Assert.Equal(row.Line, WrongUserHelperProcess.ClassifyClientFailure(row.Failure).Line));
    }

    private static readonly (Exception Failure, string Line)[] RootFailures =
    [
        (new UnauthorizedAccessException("A launch directory must be owned by the current user."), "REFUSED|owner-not-current-user"),
        (new UnauthorizedAccessException("A launch directory must be owned by the current user. "), "INCONCLUSIVE|other-refusal"),
        (new UnauthorizedAccessException("a launch directory must be owned by the current user."), "INCONCLUSIVE|other-refusal"),
        (new UnauthorizedAccessException("A launch directory must be accessible by its owner only."), "INCONCLUSIVE|other-refusal"),
        (new UnauthorizedAccessException("A launch directory is never a link or reparse point."), "INCONCLUSIVE|other-refusal"),
        (new DirectoryNotFoundException(), "INCONCLUSIVE|not-found"),
        (new ArgumentException("The runtime root is a canonical, local, fully qualified path."), "INCONCLUSIVE|invalid-root"),
        (new IOException(), "INCONCLUSIVE|error-IOException"),
    ];

    [Fact]
    public void OnlyTheExactOwnerRefusalOfALaunchRootCounts()
    {
        Assert.All(RootFailures, row => Assert.Equal(row.Line, WrongUserHelperProcess.ClassifyRootCheckFailure(row.Failure).Line));
    }

    [Fact]
    public void TheChainReachesGrpcDebugExceptionsAndAggregateMembers()
    {
        var connect = new LocalRpcConnectException("x", new UnauthorizedAccessException());
        var chain = WrongUserHelperProcess.Chain(new AggregateException(Wrapped(connect))).ToArray();

        Assert.Contains(connect, chain);
        Assert.Contains(chain, link => link is UnauthorizedAccessException);
    }

    // ---- guards ----

    [Fact]
    public void ARefusalExpectedByTheOwningAccountOrUnderRootIsInvalid()
    {
        Assert.Equal("INVALID|same-account", WrongUserHelperProcess.Guard(WrongUserExpectation.Refused, Owner.Value, Owner)?.Line);
        Assert.Null(WrongUserHelperProcess.Guard(WrongUserExpectation.AdmittedControl, Owner.Value, Owner));
        Assert.Null(WrongUserHelperProcess.Guard(WrongUserExpectation.Refused, Owner.Value, Second));
        Assert.Equal("INVALID|root", WrongUserHelperProcess.Guard(WrongUserExpectation.Refused, "1000", Root)?.Line);
        Assert.Equal("INVALID|root", WrongUserHelperProcess.Guard(WrongUserExpectation.AdmittedControl, "0", Root)?.Line);

        // The token's default owner (Administrators when elevated) is the same account as its user SID.
        var elevated = new WrongUserIdentity(Owner.Value, [Owner.Value, WrongUserHelperProcess.AdministratorsSid], IsRoot: false);
        Assert.Equal("INVALID|same-account", WrongUserHelperProcess.Guard(WrongUserExpectation.Refused, WrongUserHelperProcess.AdministratorsSid, elevated)?.Line);
    }

    [Fact]
    public async Task TheGuardsStopEveryConnectingModeBeforeItTouchesTheEndpoint()
    {
        // Nothing listens at these addresses: a guard that let the attempt run would report INCONCLUSIVE, not INVALID.
        foreach (var mode in new[]
        {
            "wrong-user-connect|unix-socket|" + SocketPath + "|" + Owner.Value + "|refused",
            "wrong-user-connect|named-pipe|af-wu-missing|" + Owner.Value + "|refused",
            "wrong-user-client|af-wu-missing|" + Owner.Value + "|refused",
        })
        {
            var (code, output, _) = await RunAsync(mode, Owner);
            Assert.Equal(WrongUserHelperProcess.ExitInvalid, code);
            Assert.Equal(["IDENTITY|" + Owner.Value, "INVALID|same-account"], output);

            var (rootCode, rootOutput, _) = await RunAsync(mode.Replace("|refused", "|admitted-control", StringComparison.Ordinal), Root);
            Assert.Equal(WrongUserHelperProcess.ExitInvalid, rootCode);
            Assert.Equal(["IDENTITY|0", "INVALID|root"], rootOutput);
        }

        var (checkCode, checkOutput, _) = await RunAsync("wrong-user-root-check|" + RootPath + "|refused", Root);
        Assert.Equal(WrongUserHelperProcess.ExitInvalid, checkCode);
        Assert.Equal("INVALID|root", checkOutput[^1]);
    }

    [Fact]
    public async Task ARawConnectToAMissingSocketIsInconclusiveNeverARefusal()
    {
        var missing = OperatingSystem.IsWindows() ? @"C:\afwu-" + Guid.NewGuid().ToString("N")[..8] + @"\c.sock" : "/tmp/afwu-" + Guid.NewGuid().ToString("N")[..8] + "/c.sock";

        var (code, output, _) = await RunAsync("wrong-user-connect|unix-socket|" + missing + "|" + Owner.Value + "|refused", Second);

        Assert.Equal(WrongUserHelperProcess.ExitInconclusive, code);
        Assert.StartsWith("INCONCLUSIVE|", output[^1], StringComparison.Ordinal);
    }

    // ---- exit codes ----

    private static readonly (string Kind, WrongUserExpectation Expect, int Code)[] ExitCodes =
    [
        ("REFUSED", WrongUserExpectation.Refused, WrongUserHelperProcess.ExitMatch),
        ("REFUSED", WrongUserExpectation.AdmittedControl, WrongUserHelperProcess.ExitMismatch),
        ("ADMITTED", WrongUserExpectation.AdmittedControl, WrongUserHelperProcess.ExitMatch),
        ("ADMITTED", WrongUserExpectation.Refused, WrongUserHelperProcess.ExitMismatch),
        ("PASSED-OWNERSHIP", WrongUserExpectation.AdmittedControl, WrongUserHelperProcess.ExitMatch),
        ("PASSED-OWNERSHIP", WrongUserExpectation.Refused, WrongUserHelperProcess.ExitMismatch),
        ("INCONCLUSIVE", WrongUserExpectation.Refused, WrongUserHelperProcess.ExitInconclusive),
        ("INCONCLUSIVE", WrongUserExpectation.AdmittedControl, WrongUserHelperProcess.ExitInconclusive),
        ("INVALID", WrongUserExpectation.Refused, WrongUserHelperProcess.ExitInvalid),
        ("INVALID", WrongUserExpectation.AdmittedControl, WrongUserHelperProcess.ExitInvalid),
    ];

    [Fact]
    public void TheExitCodeIsZeroOnlyWhenTheOutcomeIsTheExpectedOne()
    {
        Assert.All(ExitCodes, row =>
        {
            var outcome = row.Kind switch
            {
                "REFUSED" => WrongUserOutcome.Refused("access-denied"),
                "ADMITTED" => WrongUserOutcome.Admitted,
                "PASSED-OWNERSHIP" => WrongUserOutcome.PassedOwnership,
                "INCONCLUSIVE" => WrongUserOutcome.Inconclusive("timeout"),
                _ => WrongUserOutcome.Invalid("same-account"),
            };
            Assert.Equal(row.Code, WrongUserHelperProcess.ExitCode(outcome, row.Expect));
        });
    }

    // ---- identity ----

    [Fact]
    public void TheLinuxIdentityIsTheEffectiveUidOfProcSelfStatus()
    {
        var user = WrongUserIdentity.FromProcStatus("Name:\thelper\nUmask:\t0022\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n");
        Assert.Equal("1000", user.Value);
        Assert.Equal(["1000"], user.Principals);
        Assert.False(user.IsRoot);

        var setuid = WrongUserIdentity.FromProcStatus("Uid:\t1000\t0\t0\t0\n");
        Assert.Equal("0", setuid.Value);
        Assert.True(setuid.IsRoot);

        var dropped = WrongUserIdentity.FromProcStatus("Uid:\t0\t1001\t1001\t1001\n");
        Assert.Equal("1001", dropped.Value);
        Assert.False(dropped.IsRoot);

        Assert.Throws<FormatException>(() => WrongUserIdentity.FromProcStatus("Name:\thelper\nGid:\t1000\t1000\t1000\t1000\n"));
        Assert.Throws<FormatException>(() => WrongUserIdentity.FromProcStatus("Uid:\t1000\n"));
        Assert.Throws<FormatException>(() => WrongUserIdentity.FromProcStatus("Uid:\t1000\t-1\t1000\t1000\n"));
        Assert.Throws<FormatException>(() => WrongUserIdentity.FromProcStatus("Uid:\t1000\t1000\t1000\t1000\t1000\n"));
    }

    [Fact]
    public void TheCurrentIdentityNamesThisAccount()
    {
        if (!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux())
        {
            Assert.Throws<PlatformNotSupportedException>(WrongUserIdentity.Current);
            return;
        }

        var current = WrongUserIdentity.Current();
        if (OperatingSystem.IsWindows())
        {
            using var windows = WindowsIdentity.GetCurrent();
            Assert.Equal(windows.User!.Value, current.Value);
            Assert.Contains(windows.Owner!.Value, current.Principals);
            Assert.False(current.IsRoot);
        }
        else
        {
            Assert.Matches("^[0-9]+$", current.Value);
            Assert.Equal(current.Value == "0", current.IsRoot);
        }
    }

    // ---- Windows foreign launch root ----

    [Fact(Skip = WindowsOnly, SkipUnless = nameof(IsWindows))]
    [SupportedOSPlatform("windows")]
    public async Task AForeignRootIsProtectedOwnedByItsCreatorAndAdmittedForTheCreatorAsGrantee()
    {
        var parent = Directory.CreateTempSubdirectory("afwu-");
        try
        {
            var root = Path.Combine(parent.FullName, "rt");
            var user = WrongUserIdentity.Current().Value;

            var (made, madeOutput, madeError) = await RunAsync("wrong-user-foreign-root-make|" + root + "|" + user, WrongUserIdentity.Current());
            Assert.True(made == WrongUserHelperProcess.ExitMatch, madeError);
            Assert.Equal(["FOREIGN-ROOT|" + root + "|" + user + "|" + user], madeOutput);

            var security = new DirectoryInfo(root).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
            var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
            Assert.True(security.AreAccessRulesProtected);
            Assert.Equal(user, security.GetOwner(typeof(SecurityIdentifier))!.Value);
            Assert.Equal(
                new[] { user, WrongUserHelperProcess.SystemSid, WrongUserHelperProcess.AdministratorsSid }.Order(StringComparer.Ordinal),
                rules.Select(rule => rule.IdentityReference.Value).Order(StringComparer.Ordinal));
            Assert.All(rules, rule =>
            {
                Assert.Equal(AccessControlType.Allow, rule.AccessControlType);
                Assert.Equal(FileSystemRights.FullControl, rule.FileSystemRights);
                Assert.False(rule.IsInherited);
            });

            var (admitted, admittedOutput, _) = await RunAsync("wrong-user-root-check|" + root + "|admitted-control", WrongUserIdentity.Current());
            Assert.Equal(WrongUserHelperProcess.ExitMatch, admitted);
            Assert.Equal("ADMITTED", admittedOutput[^1]);

            var (invalid, invalidOutput, _) = await RunAsync("wrong-user-root-check|" + root + "|refused", WrongUserIdentity.Current());
            Assert.Equal(WrongUserHelperProcess.ExitInvalid, invalid);
            Assert.Equal("INVALID|same-account", invalidOutput[^1]);

            var (again, againOutput, _) = await RunAsync("wrong-user-foreign-root-make|" + root + "|" + user, WrongUserIdentity.Current());
            Assert.Equal(WrongUserHelperProcess.ExitInvalid, again);
            Assert.Equal(["INVALID|root-path"], againOutput);
        }
        finally
        {
            parent.Delete(recursive: true);
        }
    }

    [Fact(Skip = WindowsOnly, SkipUnless = nameof(IsWindows))]
    [SupportedOSPlatform("windows")]
    public async Task AForeignRootGrantingAnotherAccountIsRefusedForAReasonThatIsNotOwnershipAndSoProvesNothing()
    {
        var parent = Directory.CreateTempSubdirectory("afwu-");
        var root = Path.Combine(parent.FullName, "rt");
        try
        {
            var (made, _, madeError) = await RunAsync("wrong-user-foreign-root-make|" + root + "|" + OtherSid, WrongUserIdentity.Current());
            Assert.True(made == WrongUserHelperProcess.ExitMatch, madeError);

            // The creator owns the root, so the only refusal it can meet is the extra principal's rule: a real refusal that is not
            // the owner refusal is never counted.
            var (code, output, _) = await RunAsync("wrong-user-root-check|" + root + "|admitted-control", WrongUserIdentity.Current());
            Assert.Equal(WrongUserHelperProcess.ExitInconclusive, code);
            Assert.Equal("INCONCLUSIVE|other-refusal", output[^1]);
        }
        finally
        {
            // The creator is not granted access to this root, but as its owner it may rewrite the access list before removing it.
            var info = new DirectoryInfo(root);
            if (info.Exists)
            {
                var security = info.GetAccessControl();
                using var identity = WindowsIdentity.GetCurrent();
                security.AddAccessRule(new FileSystemAccessRule(identity.User!, FileSystemRights.FullControl, AccessControlType.Allow));
                info.SetAccessControl(security);
            }

            parent.Delete(recursive: true);
        }
    }

    [Fact(Skip = PipeOnly, SkipUnless = nameof(IsWindows))]
    public async Task ARawConnectToAMissingPipeIsInconclusiveNeverARefusal()
    {
        var (code, output, _) = await RunAsync("wrong-user-connect|named-pipe|af-wu-missing-" + Guid.NewGuid().ToString("N") + "|" + Owner.Value + "|refused", Second);

        Assert.Equal(WrongUserHelperProcess.ExitInconclusive, code);
        Assert.StartsWith("INCONCLUSIVE|", output[^1], StringComparison.Ordinal);
    }

    private static WrongUserRequest Parse(string mode) => WrongUserHelperProcess.Parse(mode.Split('|'));

    private static RpcException Wrapped(LocalRpcConnectException connect) =>
        new(new Status(StatusCode.Unavailable, "Error starting gRPC call.", new HttpRequestException("connect", connect)));

    private static async Task<(int Code, string[] Output, string Error)> RunAsync(string mode, WrongUserIdentity identity)
    {
        using var input = new StringReader(string.Empty);
        await using var output = new StringWriter();
        await using var error = new StringWriter();
        var code = await WrongUserHelperProcess.RunAsync(mode.Split('|'), new WrongUserConsole(input, output, error, () => identity));
        var lines = output.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return (code, lines, error.ToString());
    }
}
