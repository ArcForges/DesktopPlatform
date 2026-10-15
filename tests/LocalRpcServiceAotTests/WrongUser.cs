// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Security.Principal;
using ArcForges.LocalRpc;

/// <summary>
/// The second-account modes of the AF-DP-01 wrong-user procedure (acceptance register AR-02). The owning account serves one service-mode
/// endpoint (<c>--ar02-serve</c>); a second, standard, non-root account attempts it with a raw connect (<c>--ar02-connect</c>). Run under one
/// account these are controls of the mechanics only: a refusal expected by the account that owns the endpoint is reported INVALID, never a
/// pass.
/// </summary>
internal static class WrongUser
{
    internal const string ServeArgument = "--ar02-serve";
    internal const string ConnectArgument = "--ar02-connect";

    private const int ExitMatch = 0;
    private const int ExitMismatch = 1;
    private const int ExitInvalid = 2;
    private const int ExitInconclusive = 3;
    private const int ExitUsage = 64;

    /// <summary>
    /// Serves a service-mode endpoint with a trivial service until <c>STOP</c> on standard input (or 30 minutes), printing
    /// <c>AR02-ENDPOINT|transport|address|owner|pid</c>; <c>COUNT</c> prints the peer decisions so far. On Linux <c>--expose-socket</c> opens the
    /// socket directory to traversal (0711) and the socket to everyone (0666) after binding, so a second uid reaches the socket and meets the
    /// <c>SO_PEERCRED</c> uid check instead of the directory permission.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The temporary directory is removed in finally.")]
    internal static async Task<int> ServeAsync(bool exposeSocket)
    {
        var owner = Identity(out _);
        DirectoryInfo? root = null;
        LocalRpcEndpoint endpoint;
        if (OperatingSystem.IsWindows())
        {
            endpoint = LocalRpcEndpoint.NamedPipe("af-svc-ar02-" + Guid.NewGuid().ToString("N"));
        }
        else
        {
            root = Directory.CreateTempSubdirectory("afar02-");
            endpoint = LocalRpcEndpoint.UnixDomainSocket(Path.Combine(root.FullName, "arcforges", "node.sock"));
        }

        try
        {
            var builder = LocalRpcServer.CreateBuilder(endpoint).AddService(new ProbeService());
            builder.Options = new LocalRpcServerOptions { Mode = LocalRpcServerMode.Service };
            await using var server = builder.Build();
            await server.StartAsync().ConfigureAwait(false);
            if (exposeSocket && !OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(root!.FullName, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute);
                File.SetUnixFileMode(Path.GetDirectoryName(endpoint.Address)!, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute);
                File.SetUnixFileMode(endpoint.Address, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.OtherRead | UnixFileMode.OtherWrite);
            }

            await Say("AR02-ENDPOINT|" + (OperatingSystem.IsWindows() ? "named-pipe" : "unix-socket") + "|" + endpoint.Address + "|" + owner + "|" + Environment.ProcessId).ConfigureAwait(false);
            using var bound = new CancellationTokenSource(TimeSpan.FromMinutes(30));
            var ending = "bound";
            while (!bound.IsCancellationRequested)
            {
                string? line;
                try
                {
                    line = await Console.In.ReadLineAsync(bound.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                if (line is null)
                {
                    ending = "eof";
                    break;
                }

                if (line.Trim() == "COUNT")
                {
                    await Say(Count(server)).ConfigureAwait(false);
                }
                else if (line.Trim() == "STOP")
                {
                    ending = "stop";
                    break;
                }
            }

            await Say("AR02-STOPPED|" + ending + "|" + Count(server)).ConfigureAwait(false);
            return ExitMatch;
        }
        finally
        {
            root?.Delete(recursive: true);
        }
    }

    /// <summary>
    /// <c>--ar02-connect address owner refused|admitted-control</c>: a raw connect with no library check, so any refusal comes from the OS
    /// (the pipe's access list, the directory permission) or from the server's peer check (the connection is closed before any byte).
    /// </summary>
    [SuppressMessage("Design", "CA1031", Justification = "Every connect outcome is classified and reported.")]
    internal static async Task<int> ConnectAsync(string[] arguments)
    {
        if (arguments.Length != 3 || arguments[2] is not ("refused" or "admitted-control"))
        {
            await Console.Error.WriteLineAsync("USAGE|--ar02-connect <address> <owner SID or uid> refused|admitted-control").ConfigureAwait(false);
            return ExitUsage;
        }

        var (address, owner, expectRefused) = (arguments[0], arguments[1], arguments[2] == "refused");
        var identity = Identity(out var root);
        await Say("AR02-IDENTITY|" + identity).ConfigureAwait(false);
        if (root || (expectRefused && string.Equals(identity, owner, StringComparison.OrdinalIgnoreCase)))
        {
            await Say("INVALID|" + (root ? "root" : "same-account")).ConfigureAwait(false);
            return ExitInvalid;
        }

        string outcome;
        bool? refused;
        try
        {
            if (OperatingSystem.IsWindows())
            {
                await using var pipe = new NamedPipeClientStream(".", address, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Anonymous);
                await pipe.ConnectAsync(5000).ConfigureAwait(false);
                (outcome, refused) = await AfterConnectAsync(pipe).ConfigureAwait(false);
            }
            else
            {
                using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                using var connectBound = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await socket.ConnectAsync(new UnixDomainSocketEndPoint(address), connectBound.Token).ConfigureAwait(false);
                await using var stream = new NetworkStream(socket, ownsSocket: false);
                (outcome, refused) = await AfterConnectAsync(stream).ConfigureAwait(false);
            }
        }
        catch (UnauthorizedAccessException)
        {
            (outcome, refused) = ("REFUSED|access-denied", true);
        }
        catch (SocketException exception) when (exception.SocketErrorCode == SocketError.AccessDenied)
        {
            (outcome, refused) = ("REFUSED|eacces", true);
        }
        catch (Exception exception)
        {
            (outcome, refused) = ("INCONCLUSIVE|" + exception.GetType().Name + ": " + exception.Message, null);
        }

        await Say(outcome).ConfigureAwait(false);
        return refused switch
        {
            null => ExitInconclusive,
            true => expectRefused ? ExitMatch : ExitMismatch,
            false => expectRefused ? ExitMismatch : ExitMatch,
        };
    }

    /// <summary>
    /// After the OS let the connection through: a server that denies the peer drops the stream at once, unread; an admitted peer's connection
    /// stays open until the 10 s handshake limit, so nothing arriving within 3 s means admitted.
    /// </summary>
    private static async Task<(string Outcome, bool? Refused)> AfterConnectAsync(Stream stream)
    {
        var buffer = new byte[1];
        using var wait = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        try
        {
            var read = await stream.ReadAsync(buffer, wait.Token).ConfigureAwait(false);
            return read == 0 ? ("REFUSED|closed-by-peer-check", true) : ("INCONCLUSIVE|unexpected-byte", null);
        }
        catch (OperationCanceledException)
        {
            return ("ADMITTED", false);
        }
        catch (IOException)
        {
            return ("REFUSED|closed-by-peer-check", true);
        }
    }

    private static string Count(LocalRpcServer server)
    {
        var snapshot = server.GetServiceSnapshot();
        return string.Create(
            CultureInfo.InvariantCulture,
            $"AR02-PEERS|admitted={snapshot.PeersAdmitted}|other-user={snapshot.PeersDenied[LocalRpcPeerDenial.OtherUser]}|unresolved={snapshot.PeersDenied[LocalRpcPeerDenial.Unresolved]}|exited={snapshot.PeersDenied[LocalRpcPeerDenial.ProcessExited]}|refused={snapshot.PeersDenied[LocalRpcPeerDenial.Refused]}");
    }

    /// <summary>The account this process runs as: the user SID on Windows, the effective uid (from <c>/proc/self/status</c>) on Linux.</summary>
    private static string Identity(out bool root)
    {
        if (OperatingSystem.IsWindows())
        {
            root = false;
            using var current = WindowsIdentity.GetCurrent();
            return current.User!.Value;
        }

        foreach (var line in File.ReadAllLines("/proc/self/status"))
        {
            if (line.StartsWith("Uid:", StringComparison.Ordinal))
            {
                var effective = line["Uid:".Length..].Split(['\t', ' '], StringSplitOptions.RemoveEmptyEntries)[1];
                root = effective == "0";
                return effective;
            }
        }

        throw new InvalidOperationException("/proc/self/status has no Uid line.");
    }

    private static async Task Say(string line)
    {
        await Console.Out.WriteLineAsync(line).ConfigureAwait(false);
        await Console.Out.FlushAsync().ConfigureAwait(false);
    }
}
