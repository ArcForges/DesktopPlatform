// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using ArcForges.Contracts.LocalRpc.Platform.V1;
using Grpc.Core;

namespace ArcForges.LocalRpc.Tests;

/// <summary>Which PLT task's endpoint a wrong-user serving helper exposes.</summary>
internal enum WrongUserRoute
{
    /// <summary>PLT.09: a plain <see cref="LocalRpcServer"/>.</summary>
    Plain = 0,

    /// <summary>PLT.10: a launch endpoint of a <see cref="LocalRpcLaunchAuthority"/> with a launch-authorized server.</summary>
    Launch = 1,

    /// <summary>PLT.11: a launch endpoint behind the registration gate.</summary>
    Registration = 2,
}

/// <summary>The OS stream transport of a wrong-user helper.</summary>
internal enum WrongUserTransport
{
    /// <summary>A Windows Named Pipe.</summary>
    NamedPipe = 0,

    /// <summary>A Unix domain socket.</summary>
    UnixSocket = 1,
}

/// <summary>What the operator expects a check to observe.</summary>
internal enum WrongUserExpectation
{
    /// <summary>The second account must be refused.</summary>
    Refused = 0,

    /// <summary>A control run by the owning account: the endpoint or root must be admitted.</summary>
    AdmittedControl = 1,
}

/// <summary>The kinds of outcome a wrong-user check reports.</summary>
internal enum WrongUserOutcomeKind
{
    /// <summary>The operating system or the library refused, for the named reason.</summary>
    Refused = 0,

    /// <summary>The connection opened or the root was accepted.</summary>
    Admitted = 1,

    /// <summary>The library client's pipe-ownership check passed (the stream opened).</summary>
    PassedOwnership = 2,

    /// <summary>Nothing was proven (not found, refused by a dead listener, timed out); never counted as a refusal.</summary>
    Inconclusive = 3,

    /// <summary>The check cannot prove anything as run (same account, root, wrong platform).</summary>
    Invalid = 4,
}

/// <summary>One observed outcome; <see cref="Line"/> is the exact text the helper prints.</summary>
internal sealed record WrongUserOutcome(WrongUserOutcomeKind Kind, string? Detail)
{
    internal static WrongUserOutcome Admitted { get; } = new(WrongUserOutcomeKind.Admitted, null);

    internal static WrongUserOutcome PassedOwnership { get; } = new(WrongUserOutcomeKind.PassedOwnership, null);

    internal string Line => Kind switch
    {
        WrongUserOutcomeKind.Refused => "REFUSED|" + Detail,
        WrongUserOutcomeKind.Admitted => "ADMITTED",
        WrongUserOutcomeKind.PassedOwnership => "PASSED-OWNERSHIP",
        WrongUserOutcomeKind.Inconclusive => "INCONCLUSIVE|" + Detail,
        _ => "INVALID|" + Detail,
    };

    internal static WrongUserOutcome Refused(string detail) => new(WrongUserOutcomeKind.Refused, detail);

    internal static WrongUserOutcome Inconclusive(string detail) => new(WrongUserOutcomeKind.Inconclusive, detail);

    internal static WrongUserOutcome Invalid(string detail) => new(WrongUserOutcomeKind.Invalid, detail);
}

/// <summary>
/// The account a helper runs as, read without any native binding: the Windows user SID (plus the token's default owner, which is
/// what the runtime's pipe-ownership check compares) or the Linux effective uid from <c>/proc/self/status</c>.
/// </summary>
internal sealed record WrongUserIdentity(string Value, IReadOnlyList<string> Principals, bool IsRoot)
{
    internal static WrongUserIdentity Current()
    {
        if (OperatingSystem.IsWindows())
        {
            return CurrentWindows();
        }

        if (OperatingSystem.IsLinux())
        {
            return FromProcStatus(File.ReadAllText("/proc/self/status"));
        }

        throw new PlatformNotSupportedException("The wrong-user procedure runs on Windows and Linux only.");
    }

    /// <summary>Reads the effective uid from the text of <c>/proc/self/status</c> (<c>Uid:</c> real, effective, saved, filesystem).</summary>
    internal static WrongUserIdentity FromProcStatus(string status)
    {
        ArgumentNullException.ThrowIfNull(status);
        foreach (var line in status.Split('\n'))
        {
            if (!line.StartsWith("Uid:", StringComparison.Ordinal))
            {
                continue;
            }

            var fields = line["Uid:".Length..].Split(['\t', ' '], StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length != 4 || !fields.All(field => uint.TryParse(field, NumberStyles.None, CultureInfo.InvariantCulture, out _)))
            {
                throw new FormatException("The Uid line of /proc/self/status holds four unsigned numbers.");
            }

            var effective = uint.Parse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture);
            var value = effective.ToString(CultureInfo.InvariantCulture);
            return new WrongUserIdentity(value, [value], effective == 0);
        }

        throw new FormatException("/proc/self/status has no Uid line.");
    }

    /// <summary>Whether <paramref name="owner"/> names this account.</summary>
    internal bool Is(string owner) => Principals.Any(principal => string.Equals(principal, owner, StringComparison.OrdinalIgnoreCase));

    [SupportedOSPlatform("windows")]
    private static WrongUserIdentity CurrentWindows()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var user = identity.User?.Value ?? throw new InvalidOperationException("The current Windows account has no SID.");
        var owner = identity.Owner?.Value;
        return new WrongUserIdentity(
            user,
            owner is null || string.Equals(owner, user, StringComparison.OrdinalIgnoreCase) ? [user] : [user, owner],
            IsRoot: false);
    }
}

/// <summary>The streams and identity a wrong-user helper uses; offline tests replace them.</summary>
internal sealed record WrongUserConsole(TextReader In, TextWriter Out, TextWriter Error, Func<WrongUserIdentity> Identity)
{
    internal static WrongUserConsole Standard => new(Console.In, Console.Out, Console.Error, WrongUserIdentity.Current);
}

/// <summary>A parsed wrong-user helper mode.</summary>
internal abstract record WrongUserRequest;

/// <summary><c>wrong-user-serve|route|transport</c>.</summary>
internal sealed record WrongUserServe(WrongUserRoute Route, WrongUserTransport Transport) : WrongUserRequest;

/// <summary><c>wrong-user-connect|transport|address|owner|expect</c>.</summary>
internal sealed record WrongUserConnect(WrongUserTransport Transport, string Address, string Owner, WrongUserExpectation Expect) : WrongUserRequest;

/// <summary><c>wrong-user-squat-pipe|name</c> (Windows).</summary>
internal sealed record WrongUserSquatPipe(string Name) : WrongUserRequest;

/// <summary><c>wrong-user-client|name|squatter owner|expect</c> (Windows).</summary>
internal sealed record WrongUserClient(string Name, string Owner, WrongUserExpectation Expect) : WrongUserRequest;

/// <summary><c>wrong-user-foreign-root-make|path|grantee SID</c> (Windows).</summary>
internal sealed record WrongUserForeignRootMake(string Path, string Grantee) : WrongUserRequest;

/// <summary><c>wrong-user-root-check|path|expect</c> (Windows).</summary>
internal sealed record WrongUserRootCheck(string Path, WrongUserExpectation Expect) : WrongUserRequest;

/// <summary>
/// The helper modes of the wrong-user procedure (Tests/wrong-user-procedure.md). They are reached only through the test assembly's
/// startup hook with <see cref="LaunchHelperProcess.Variable"/> naming a <c>wrong-user-*</c> mode, so a normal test run never takes
/// this path. No check here can run across two accounts by itself: the serving and squatting modes run as the owning account and
/// the connecting, client and root-check modes as the second account. Run under one account they are controls only, never
/// wrong-user evidence; a refusal expectation run by the owning account is reported INVALID, never a pass.
/// </summary>
internal static class WrongUserHelperProcess
{
    internal const string Prefix = "wrong-user-";

    /// <summary>The observed outcome is the expected one.</summary>
    internal const int ExitMatch = 0;

    /// <summary>The observed outcome contradicts the expectation (for example a second account was admitted).</summary>
    internal const int ExitMismatch = 1;

    /// <summary>The check proved nothing as run (same account, root, wrong platform).</summary>
    internal const int ExitInvalid = 2;

    /// <summary>Nothing was observed that settles the question (not found, refused by a dead listener, timed out).</summary>
    internal const int ExitInconclusive = 3;

    /// <summary>The mode or its arguments are malformed.</summary>
    internal const int ExitUsage = 64;

    /// <summary>The exact refusal of a launch root owned by another account (LaunchDirectory.RequireOwnerOnlyWindows).</summary>
    internal const string OwnerRefusalMessage = "A launch directory must be owned by the current user.";

    internal const string AdministratorsSid = "S-1-5-32-544";

    internal const string SystemSid = "S-1-5-18";

    private const int PipeBusyHResult = unchecked((int)0x800700E7);

    internal static TimeSpan ConnectTimeout { get; } = TimeSpan.FromSeconds(5);

    internal static TimeSpan ServeBound { get; } = TimeSpan.FromMinutes(30);

    [SuppressMessage("Design", "CA1031", Justification = "A helper reports any failure on stderr and through its exit code.")]
    internal static async Task<int> RunAsync(IReadOnlyList<string> arguments, WrongUserConsole console)
    {
        ArgumentNullException.ThrowIfNull(console);
        WrongUserRequest request;
        try
        {
            request = Parse(arguments);
        }
        catch (FormatException exception)
        {
            await WriteAsync(console.Error, "USAGE|" + exception.Message).ConfigureAwait(false);
            return ExitUsage;
        }

        return request switch
        {
            WrongUserServe serve => await ServeAsync(serve, console).ConfigureAwait(false),
            WrongUserConnect connect => await ReportAsync(console, connect.Expect, identity => ConnectAsync(connect, identity)).ConfigureAwait(false),
            WrongUserClient client => await ReportAsync(console, client.Expect, identity => ClientAsync(client, identity)).ConfigureAwait(false),
            WrongUserRootCheck check => await ReportAsync(console, check.Expect, identity => RootCheckAsync(check, identity)).ConfigureAwait(false),
            WrongUserSquatPipe squat => await SquatAsync(squat, console).ConfigureAwait(false),
            WrongUserForeignRootMake make => await ForeignRootMakeAsync(make, console).ConfigureAwait(false),
            _ => ExitUsage,
        };
    }

    // ---- parsing ----

    internal static WrongUserRequest Parse(IReadOnlyList<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        if (arguments.Count == 0)
        {
            throw new FormatException("No wrong-user mode was named.");
        }

        switch (arguments[0])
        {
            case "wrong-user-serve":
                Arity(arguments, 3);
                return new WrongUserServe(ParseRoute(arguments[1]), ParseTransport(arguments[2]));
            case "wrong-user-connect":
                Arity(arguments, 5);
                return ParseConnect(arguments);
            case "wrong-user-squat-pipe":
                Arity(arguments, 2);
                return new WrongUserSquatPipe(ParseAddress(WrongUserTransport.NamedPipe, arguments[1]));
            case "wrong-user-client":
                Arity(arguments, 4);
                return new WrongUserClient(ParseAddress(WrongUserTransport.NamedPipe, arguments[1]), ParseOwner(arguments[2]), ParseExpectation(arguments[3]));
            case "wrong-user-foreign-root-make":
                Arity(arguments, 3);
                return new WrongUserForeignRootMake(ParseRootPath(arguments[1]), ParseSid(arguments[2]));
            case "wrong-user-root-check":
                Arity(arguments, 3);
                return new WrongUserRootCheck(ParseRootPath(arguments[1]), ParseExpectation(arguments[2]));
            default:
                throw new FormatException("Unknown wrong-user mode '" + arguments[0] + "'.");
        }
    }

    private static WrongUserConnect ParseConnect(IReadOnlyList<string> arguments)
    {
        var transport = ParseTransport(arguments[1]);
        return new WrongUserConnect(transport, ParseAddress(transport, arguments[2]), ParseOwner(arguments[3]), ParseExpectation(arguments[4]));
    }

    internal static string TransportToken(WrongUserTransport transport) =>
        transport == WrongUserTransport.NamedPipe ? "named-pipe" : "unix-socket";

    private static void Arity(IReadOnlyList<string> arguments, int count)
    {
        if (arguments.Count != count)
        {
            throw new FormatException(arguments[0] + " takes " + (count - 1).ToString(CultureInfo.InvariantCulture) + " '|'-separated arguments.");
        }
    }

    private static WrongUserRoute ParseRoute(string token) => token switch
    {
        "plain" => WrongUserRoute.Plain,
        "launch" => WrongUserRoute.Launch,
        "registration" => WrongUserRoute.Registration,
        _ => throw new FormatException("The route is plain, launch or registration."),
    };

    private static WrongUserTransport ParseTransport(string token) => token switch
    {
        "named-pipe" => WrongUserTransport.NamedPipe,
        "unix-socket" => WrongUserTransport.UnixSocket,
        _ => throw new FormatException("The transport is named-pipe or unix-socket."),
    };

    private static WrongUserExpectation ParseExpectation(string token) => token switch
    {
        "refused" => WrongUserExpectation.Refused,
        "admitted-control" => WrongUserExpectation.AdmittedControl,
        _ => throw new FormatException("The expectation is refused or admitted-control."),
    };

    private static string ParseAddress(WrongUserTransport transport, string address)
    {
        try
        {
            return transport == WrongUserTransport.NamedPipe
                ? LocalRpcEndpoint.ValidatePipeName(address)
                : LocalRpcEndpoint.ValidateSocketPath(address);
        }
        catch (ArgumentException exception)
        {
            throw new FormatException(exception.Message, exception);
        }
    }

    /// <summary>An owner is a Windows SID (<c>S-1-...</c>) or a Linux uid (decimal).</summary>
    private static string ParseOwner(string owner)
    {
        if (IsSid(owner) || (owner.Length is > 0 and <= 10 && uint.TryParse(owner, NumberStyles.None, CultureInfo.InvariantCulture, out _)))
        {
            return owner;
        }

        throw new FormatException("An owner is a Windows SID (S-1-...) or a decimal Linux uid.");
    }

    private static string ParseSid(string sid) =>
        IsSid(sid) ? sid : throw new FormatException("A grantee is a Windows SID (S-1-...).");

    private static bool IsSid(string value)
    {
        if (!value.StartsWith("S-1-", StringComparison.Ordinal) || value.Length > 184)
        {
            return false;
        }

        var parts = value[4..].Split('-');
        return parts.Length >= 2 && parts.All(part => part.Length is > 0 and <= 10 && part.All(char.IsAsciiDigit));
    }

    /// <summary>A launch root path as <see cref="LocalRpcLaunchAuthority.Create(string, TimeSpan?)"/> accepts it: canonical, local, fully qualified.</summary>
    private static string ParseRootPath(string path)
    {
        if (path.Length == 0 || path.Contains('\0', StringComparison.Ordinal) || path.StartsWith(@"\\", StringComparison.Ordinal)
            || !Path.IsPathFullyQualified(path) || path[^1] == Path.DirectorySeparatorChar
            || !string.Equals(Path.GetFullPath(path), path, StringComparison.Ordinal))
        {
            throw new FormatException("A root path is canonical, local and fully qualified, without a trailing separator.");
        }

        return path;
    }

    // ---- guards, classification and exit codes ----

    /// <summary>
    /// Refuses to let a check pass when it cannot prove anything: Linux root bypasses discretionary access control, and a refusal
    /// expected by the account that owns the endpoint (or root) is no wrong-user observation.
    /// </summary>
    internal static WrongUserOutcome? Guard(WrongUserExpectation expect, string owner, WrongUserIdentity current)
    {
        ArgumentNullException.ThrowIfNull(current);
        if (current.IsRoot)
        {
            return WrongUserOutcome.Invalid("root");
        }

        return expect == WrongUserExpectation.Refused && current.Is(owner) ? WrongUserOutcome.Invalid("same-account") : null;
    }

    internal static int ExitCode(WrongUserOutcome outcome, WrongUserExpectation expect)
    {
        ArgumentNullException.ThrowIfNull(outcome);
        return outcome.Kind switch
        {
            WrongUserOutcomeKind.Invalid => ExitInvalid,
            WrongUserOutcomeKind.Inconclusive => ExitInconclusive,
            WrongUserOutcomeKind.Refused => expect == WrongUserExpectation.Refused ? ExitMatch : ExitMismatch,
            _ => expect == WrongUserExpectation.AdmittedControl ? ExitMatch : ExitMismatch,
        };
    }

    /// <summary>
    /// Classifies a raw connect failure. Only an access-denied answer from the operating system is a refusal; a missing endpoint, a
    /// refused connection (no listener), a busy pipe or a timeout proves nothing about the second account.
    /// </summary>
    internal static WrongUserOutcome ClassifyConnectFailure(Exception exception) => exception switch
    {
        UnauthorizedAccessException => WrongUserOutcome.Refused("access-denied"),
        SocketException socket => socket.SocketErrorCode switch
        {
            SocketError.AccessDenied => WrongUserOutcome.Refused("access-denied"),
            SocketError.ConnectionRefused => WrongUserOutcome.Inconclusive("refused"),
            SocketError.AddressNotAvailable => WrongUserOutcome.Inconclusive("not-found"),
            SocketError.TimedOut => WrongUserOutcome.Inconclusive("timeout"),
            _ => WrongUserOutcome.Inconclusive("socket-" + socket.SocketErrorCode),
        },
        TimeoutException or OperationCanceledException => WrongUserOutcome.Inconclusive("timeout"),
        FileNotFoundException or DirectoryNotFoundException => WrongUserOutcome.Inconclusive("not-found"),
        IOException { HResult: PipeBusyHResult } => WrongUserOutcome.Inconclusive("busy"),
        IOException => WrongUserOutcome.Inconclusive("io"),
        _ => WrongUserOutcome.Inconclusive("error-" + exception.GetType().Name),
    };

    /// <summary>
    /// Classifies a failed library-client call. It is a refusal exactly when the chain holds the library's connect failure wrapping
    /// an <see cref="UnauthorizedAccessException"/> (the runtime's CurrentUserOnly ownership check, or the endpoint's access list);
    /// any other connect failure proves nothing; a failure after the stream opened means the ownership check passed.
    /// </summary>
    internal static WrongUserOutcome ClassifyClientFailure(Exception exception)
    {
        foreach (var link in Chain(exception))
        {
            if (link is LocalRpcConnectException connect)
            {
                return connect.InnerException is UnauthorizedAccessException
                    ? WrongUserOutcome.Refused("not-owned-by-current-user")
                    : WrongUserOutcome.Inconclusive("connect-" + ClassifyConnectFailure(connect.InnerException ?? connect).Detail);
            }
        }

        return WrongUserOutcome.PassedOwnership;
    }

    /// <summary>Classifies a refused launch root. Only the exact owner refusal counts; any other refusal proves nothing about ownership.</summary>
    internal static WrongUserOutcome ClassifyRootCheckFailure(Exception exception) => exception switch
    {
        UnauthorizedAccessException refusal when string.Equals(refusal.Message, OwnerRefusalMessage, StringComparison.Ordinal)
            => WrongUserOutcome.Refused("owner-not-current-user"),
        UnauthorizedAccessException => WrongUserOutcome.Inconclusive("other-refusal"),
        DirectoryNotFoundException => WrongUserOutcome.Inconclusive("not-found"),
        ArgumentException => WrongUserOutcome.Inconclusive("invalid-root"),
        _ => WrongUserOutcome.Inconclusive("error-" + exception.GetType().Name),
    };

    /// <summary>Every exception reachable from <paramref name="exception"/>: inner exceptions, aggregate members and gRPC debug exceptions.</summary>
    internal static IEnumerable<Exception> Chain(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        var pending = new Stack<Exception>();
        pending.Push(exception);
        var visited = 0;
        while (pending.Count > 0 && visited++ < 64)
        {
            var current = pending.Pop();
            yield return current;
            if (current is RpcException { Status.DebugException: { } debug })
            {
                pending.Push(debug);
            }

            if (current is AggregateException aggregate)
            {
                foreach (var inner in aggregate.InnerExceptions)
                {
                    pending.Push(inner);
                }
            }
            else if (current.InnerException is { } inner)
            {
                pending.Push(inner);
            }
        }
    }

    // ---- connecting modes ----

    private static async Task<int> ReportAsync(WrongUserConsole console, WrongUserExpectation expect, Func<WrongUserIdentity, Task<WrongUserOutcome>> check)
    {
        var identity = console.Identity();
        await WriteAsync(console.Out, "IDENTITY|" + identity.Value).ConfigureAwait(false);
        var outcome = await check(identity).ConfigureAwait(false);
        await WriteAsync(console.Out, outcome.Line).ConfigureAwait(false);
        return ExitCode(outcome, expect);
    }

    [SuppressMessage("Design", "CA1031", Justification = "Every connect failure is classified; none may escape as a crash that hides the outcome.")]
    private static async Task<WrongUserOutcome> ConnectAsync(WrongUserConnect request, WrongUserIdentity identity)
    {
        if (Guard(request.Expect, request.Owner, identity) is { } invalid)
        {
            return invalid;
        }

        if (request.Transport == WrongUserTransport.NamedPipe && !OperatingSystem.IsWindows())
        {
            return WrongUserOutcome.Invalid("unsupported-platform");
        }

        try
        {
            if (request.Transport == WrongUserTransport.NamedPipe)
            {
                // No CurrentUserOnly and no library checks: any refusal comes from the server end's own access list.
                await using var pipe = new NamedPipeClientStream(".", request.Address, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Anonymous);
                await pipe.ConnectAsync((int)ConnectTimeout.TotalMilliseconds).ConfigureAwait(false);
            }
            else
            {
                // A raw socket: no owner-only directory check of the library client runs, so any refusal comes from the kernel.
                using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                using var bounded = new CancellationTokenSource(ConnectTimeout);
                await socket.ConnectAsync(new UnixDomainSocketEndPoint(request.Address), bounded.Token).ConfigureAwait(false);
            }

            return WrongUserOutcome.Admitted;
        }
        catch (Exception exception)
        {
            return ClassifyConnectFailure(exception);
        }
    }

    [SuppressMessage("Design", "CA1031", Justification = "Every client failure is classified; none may escape as a crash that hides the outcome.")]
    private static async Task<WrongUserOutcome> ClientAsync(WrongUserClient request, WrongUserIdentity identity)
    {
        if (Guard(request.Expect, request.Owner, identity) is { } invalid)
        {
            return invalid;
        }

        if (!OperatingSystem.IsWindows())
        {
            return WrongUserOutcome.Invalid("unsupported-platform");
        }

        try
        {
            await using var channel = LocalRpcClientChannel.Create(LocalRpcEndpoint.NamedPipe(request.Name), new LocalRpcLimits { ConnectTimeout = ConnectTimeout });
            var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);
            _ = await client.ChallengeAsync(Requests.Challenge(8), deadline: DateTime.UtcNow + TimeSpan.FromSeconds(15));
            return WrongUserOutcome.PassedOwnership;
        }
        catch (Exception exception)
        {
            return ClassifyClientFailure(exception);
        }
    }

    [SuppressMessage("Design", "CA1031", Justification = "Every launch-root failure is classified; none may escape as a crash that hides the outcome.")]
    private static async Task<WrongUserOutcome> RootCheckAsync(WrongUserRootCheck request, WrongUserIdentity identity)
    {
        if (identity.IsRoot)
        {
            return WrongUserOutcome.Invalid("root");
        }

        if (!OperatingSystem.IsWindows())
        {
            return WrongUserOutcome.Invalid("unsupported-platform");
        }

        string owner;
        try
        {
            owner = DirectoryOwner(request.Path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return WrongUserOutcome.Inconclusive(exception is DirectoryNotFoundException or FileNotFoundException ? "not-found" : "owner-unreadable");
        }

        // An Administrators-owned root is accepted by design, so it can never show the owner refusal.
        if (request.Expect == WrongUserExpectation.Refused && string.Equals(owner, AdministratorsSid, StringComparison.OrdinalIgnoreCase))
        {
            return WrongUserOutcome.Invalid("administrators-owned");
        }

        if (Guard(request.Expect, owner, identity) is { } invalid)
        {
            return invalid;
        }

        try
        {
            await using var authority = LocalRpcLaunchAuthority.Create(request.Path);
            return WrongUserOutcome.Admitted;
        }
        catch (Exception exception)
        {
            return ClassifyRootCheckFailure(exception);
        }
    }

    // ---- owning-account modes ----

    private static async Task<int> ServeAsync(WrongUserServe request, WrongUserConsole console)
    {
        if (request.Transport == WrongUserTransport.NamedPipe && !OperatingSystem.IsWindows())
        {
            await WriteAsync(console.Out, WrongUserOutcome.Invalid("unsupported-platform").Line).ConfigureAwait(false);
            return ExitInvalid;
        }

        var identity = console.Identity();
        var served = await ServedEndpoint.StartAsync(request.Route, request.Transport).ConfigureAwait(false);
        string reason;
        try
        {
            await WriteAsync(console.Out, string.Join('|',
                "SERVING",
                TransportToken(request.Transport),
                served.Endpoint.Address,
                identity.Value,
                Environment.ProcessId.ToString(CultureInfo.InvariantCulture))).ConfigureAwait(false);
            reason = await WaitForStopAsync(console.In).ConfigureAwait(false);
        }
        finally
        {
            await served.DisposeAsync().ConfigureAwait(false);
        }

        await WriteAsync(console.Out, "STOPPED|" + reason).ConfigureAwait(false);
        return ExitMatch;
    }

    private static async Task<int> SquatAsync(WrongUserSquatPipe request, WrongUserConsole console)
    {
        if (!OperatingSystem.IsWindows())
        {
            await WriteAsync(console.Out, WrongUserOutcome.Invalid("unsupported-platform").Line).ConfigureAwait(false);
            return ExitInvalid;
        }

        var security = SquatterSecurity();
        var current = CreateSquatter(request.Name, security);
        var accepted = 0;
        string reason;
        using var stopping = new CancellationTokenSource();
        try
        {
            var owner = current.GetAccessControl().GetOwner(typeof(SecurityIdentifier))?.Value ?? "unknown";
            await WriteAsync(console.Out, "SQUATTING|" + request.Name + "|" + owner).ConfigureAwait(false);
            var stop = WaitForStopAsync(console.In);
            while (true)
            {
                var connection = current.WaitForConnectionAsync(stopping.Token);
                if (await Task.WhenAny(connection, stop).ConfigureAwait(false) == stop)
                {
                    reason = await stop.ConfigureAwait(false);
                    await stopping.CancelAsync().ConfigureAwait(false);
                    await Quietly(connection).ConfigureAwait(false);
                    break;
                }

                await connection.ConfigureAwait(false);
                accepted++;

                // The next instance exists before this one closes, so a client never finds the name missing.
                var next = CreateSquatter(request.Name, security);
                await current.DisposeAsync().ConfigureAwait(false);
                current = next;
            }
        }
        finally
        {
            await current.DisposeAsync().ConfigureAwait(false);
        }

        await WriteAsync(console.Out, "STOPPED|" + reason + "|accepted=" + accepted.ToString(CultureInfo.InvariantCulture)).ConfigureAwait(false);
        return ExitMatch;
    }

    private static async Task<int> ForeignRootMakeAsync(WrongUserForeignRootMake request, WrongUserConsole console)
    {
        if (!OperatingSystem.IsWindows())
        {
            await WriteAsync(console.Out, WrongUserOutcome.Invalid("unsupported-platform").Line).ConfigureAwait(false);
            return ExitInvalid;
        }

        var parent = Path.GetDirectoryName(request.Path);
        if (string.IsNullOrEmpty(parent) || !Directory.Exists(parent) || Directory.Exists(request.Path) || File.Exists(request.Path))
        {
            await WriteAsync(console.Out, WrongUserOutcome.Invalid("root-path").Line).ConfigureAwait(false);
            return ExitInvalid;
        }

        SecurityIdentifier user;
        using (var identity = WindowsIdentity.GetCurrent())
        {
            user = identity.User ?? throw new InvalidOperationException("The current Windows account has no SID.");
        }

        var grantee = new SecurityIdentifier(request.Grantee);
        new DirectoryInfo(request.Path).Create(ForeignRootSecurity(user, grantee));
        var owner = DirectoryOwner(request.Path);
        if (!string.Equals(owner, user.Value, StringComparison.OrdinalIgnoreCase))
        {
            Directory.Delete(request.Path);
            await WriteAsync(console.Out, WrongUserOutcome.Invalid("owner-not-creator").Line).ConfigureAwait(false);
            return ExitInvalid;
        }

        await WriteAsync(console.Out, string.Join('|', "FOREIGN-ROOT", request.Path, owner, grantee.Value)).ConfigureAwait(false);
        return ExitMatch;
    }

    /// <summary>
    /// The access list of a foreign launch root: protected (nothing inherited), owned by the creating account, granting full control
    /// only to the grantee, SYSTEM and Administrators. Every rule is one the launch authority accepts for the grantee, so for the
    /// grantee only the owner rule can refuse it.
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal static DirectorySecurity ForeignRootSecurity(SecurityIdentifier owner, SecurityIdentifier grantee)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(grantee);
        var security = new DirectorySecurity();
        security.SetOwner(owner);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        var principals = new[]
        {
            grantee,
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
        };
        foreach (var principal in principals.Distinct())
        {
            security.AddAccessRule(new FileSystemAccessRule(
                principal,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }

        return security;
    }

    [SupportedOSPlatform("windows")]
    internal static string DirectoryOwner(string path) =>
        new DirectoryInfo(path).GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier))?.Value
            ?? throw new UnauthorizedAccessException("The directory has no readable owner.");

    /// <summary>The squatter's permissive access list: the creating account and every authenticated user may open it.</summary>
    [SupportedOSPlatform("windows")]
    private static PipeSecurity SquatterSecurity()
    {
        SecurityIdentifier user;
        using (var identity = WindowsIdentity.GetCurrent())
        {
            user = identity.User ?? throw new InvalidOperationException("The current Windows account has no SID.");
        }

        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(user, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        return security;
    }

    [SupportedOSPlatform("windows")]
    private static NamedPipeServerStream CreateSquatter(string name, PipeSecurity security) => NamedPipeServerStreamAcl.Create(
        name,
        PipeDirection.InOut,
        NamedPipeServerStream.MaxAllowedServerInstances,
        PipeTransmissionMode.Byte,
        PipeOptions.Asynchronous,
        0,
        0,
        security);

    /// <summary>Waits for a <c>STOP</c> line, the end of standard input or the serve bound, whichever comes first.</summary>
    private static async Task<string> WaitForStopAsync(TextReader input)
    {
        // Console input reads synchronously, so the read runs on its own thread; the process exits soon after either way.
        var reading = Task.Run(() =>
        {
            string? line;
            while ((line = input.ReadLine()) is not null)
            {
                if (string.Equals(line.Trim(), "STOP", StringComparison.Ordinal))
                {
                    return "stop";
                }
            }

            return "end-of-input";
        });
        var winner = await Task.WhenAny(reading, Task.Delay(ServeBound)).ConfigureAwait(false);
        return winner == reading ? await reading.ConfigureAwait(false) : "bound";
    }

    private static async Task Quietly(Task task)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Cancelled on stop, as intended.
        }
    }

    private static async Task WriteAsync(TextWriter writer, string line)
    {
        await writer.WriteLineAsync(line).ConfigureAwait(false);
        await writer.FlushAsync().ConfigureAwait(false);
    }

    /// <summary>A live endpoint of one route over one transport and everything it owns, removed on dispose.</summary>
    private sealed class ServedEndpoint : IAsyncDisposable
    {
        private DirectoryInfo? _directory;
        private LocalRpcLaunchAuthority? _authority;
        private LocalRpcLaunch? _launch;
        private LocalRpcRegistration? _registration;
        private LocalRpcServer? _server;

        internal LocalRpcEndpoint Endpoint { get; private set; } = null!;

        internal static async Task<ServedEndpoint> StartAsync(WrongUserRoute route, WrongUserTransport transport)
        {
            var served = new ServedEndpoint();
            try
            {
                await served.BuildAsync(route, transport).ConfigureAwait(false);
                return served;
            }
            catch
            {
                await served.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (_server is not null)
            {
                await _server.DisposeAsync().ConfigureAwait(false);
            }

            if (_registration is not null)
            {
                await _registration.DisposeAsync().ConfigureAwait(false);
            }

            if (_launch is not null)
            {
                await _launch.DisposeAsync().ConfigureAwait(false);
            }

            if (_authority is not null)
            {
                await _authority.DisposeAsync().ConfigureAwait(false);
            }

            try
            {
                _directory?.Delete(recursive: true);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                // Best effort: the temporary directory holds no secret.
            }
        }

        private async Task BuildAsync(WrongUserRoute route, WrongUserTransport transport)
        {
            LocalRpcServerBuilder builder;
            if (route == WrongUserRoute.Plain)
            {
                if (transport == WrongUserTransport.NamedPipe)
                {
                    Endpoint = LocalRpcEndpoint.NamedPipe("af-wu-" + Guid.NewGuid().ToString("N"));
                }
                else
                {
                    _directory = Directory.CreateTempSubdirectory("afwu-");
                    var path = Path.Combine(_directory.FullName, "c.sock");
                    Endpoint = OperatingSystem.IsWindows()
                        ? LocalRpcEndpoint.CreateForVerification(LocalRpcTransport.UnixDomainSocket, path)
                        : LocalRpcEndpoint.UnixDomainSocket(path);
                }

                builder = LocalRpcServer.CreateBuilder(Endpoint).AddService(new RecordingBootstrapService());
            }
            else
            {
                _directory = Directory.CreateTempSubdirectory("afwu-");
                _authority = LocalRpcLaunchAuthority.Create(
                    Path.Combine(_directory.FullName, "rt"),
                    TimeSpan.FromMinutes(5),
                    new LaunchEnvironment { ForceUnixSocket = transport == WrongUserTransport.UnixSocket });
                _launch = _authority.Launch("slot-wu", Launches.Identity());
                Endpoint = _launch.Endpoint!;
                builder = LocalRpcServer.CreateBuilder(Endpoint);
                if (route == WrongUserRoute.Registration)
                {
                    _registration = LocalRpcRegistration.Create(_launch);
                    builder = builder.RequireRegistration(_registration).AddService(new BootstrapAdapter());
                }
                else
                {
                    builder = builder.AddService(new RecordingBootstrapService()).AuthorizeConnectionsAsync(_launch.AuthorizeConnectionAsync);
                }
            }

            _server = builder.Build();
            await _server.StartAsync().ConfigureAwait(false);
        }
    }
}
