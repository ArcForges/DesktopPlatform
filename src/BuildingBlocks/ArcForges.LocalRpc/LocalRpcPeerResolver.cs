// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Globalization;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace ArcForges.LocalRpc;

/// <summary>When a service-mode connection was accepted, on the clocks the peer's start time is compared with.</summary>
/// <param name="Utc">The wall clock right after the accept returned (Windows process creation times use the same clock).</param>
/// <param name="LinuxUptimeTicks">On Linux, <c>/proc/uptime</c> in clock ticks (USER_HZ 100) right after the accept; the peer's start is on this clock.</param>
internal readonly record struct LocalRpcAcceptMoment(DateTime Utc, long? LinuxUptimeTicks)
{
    internal static LocalRpcAcceptMoment Now() => new(DateTime.UtcNow, OperatingSystem.IsLinux() ? LocalRpcLinuxProc.UptimeTicks() : null);
}

/// <summary>The outcome of resolving one accepted connection's peer: an identity, or the reason the connection is dropped.</summary>
internal readonly record struct LocalRpcPeerResolution(LocalRpcPeer? Peer, LocalRpcPeerDenial Denial)
{
    internal static LocalRpcPeerResolution Of(LocalRpcPeer peer) => new(peer, LocalRpcPeerDenial.None);

    internal static LocalRpcPeerResolution Deny(LocalRpcPeerDenial denial) => new(null, denial);
}

/// <summary>Resolves the peer of one accepted service-mode stream. It runs before HTTP/2 reads a byte and must not read the stream.</summary>
internal abstract class LocalRpcPeerResolver
{
    internal abstract LocalRpcPeerResolution Resolve(Stream stream, LocalRpcAcceptMoment accepted);
}

/// <summary>
/// The operating system's answer (AD-0013 refactor §1.2.4). Windows: <c>GetNamedPipeClientProcessId</c>, then
/// <c>OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)</c>, the token user SID, <c>GetProcessTimes</c> and the image path, all through the one
/// process handle. Linux: <c>SO_PEERCRED</c> (pid, uid, gid), <c>/proc/&lt;pid&gt;/stat</c> for the start and <c>/proc/&lt;pid&gt;/exe</c>.
/// A peer that is gone when it is queried, or whose process id names a process started after the accept (a reused id), is denied; a peer
/// of another user is denied.
/// </summary>
internal sealed class LocalRpcOsPeerResolver : LocalRpcPeerResolver
{
    private static readonly Lazy<string?> CurrentSid = new(ReadCurrentSid);
    private static readonly Lazy<uint?> CurrentUid = new(() => OperatingSystem.IsLinux() ? LocalRpcLinuxProc.EffectiveUid(File.ReadAllText("/proc/self/status")) : null);

    /// <summary>Test seam: runs with the process id the OS reported, before the process is queried (to make a peer exit first).</summary>
    internal Action<int>? BeforeProcessQuery { get; init; }

    internal static string? CurrentUserSid => CurrentSid.Value;

    internal static uint? CurrentEffectiveUid => CurrentUid.Value;

    internal override LocalRpcPeerResolution Resolve(Stream stream, LocalRpcAcceptMoment accepted)
    {
        if (OperatingSystem.IsWindows())
        {
            return stream is NamedPipeServerStream pipe ? ResolveWindows(pipe, accepted) : LocalRpcPeerResolution.Deny(LocalRpcPeerDenial.Unresolved);
        }

        if (OperatingSystem.IsLinux())
        {
            return stream is NetworkStream { Socket.AddressFamily: AddressFamily.Unix } network
                ? ResolveLinux(network.Socket, accepted)
                : LocalRpcPeerResolution.Deny(LocalRpcPeerDenial.Unresolved);
        }

        return LocalRpcPeerResolution.Deny(LocalRpcPeerDenial.Unresolved);
    }

    [SupportedOSPlatform("windows")]
    private LocalRpcPeerResolution ResolveWindows(NamedPipeServerStream pipe, LocalRpcAcceptMoment accepted)
    {
        if (LocalRpcWindowsNative.ClientProcessId(pipe) is not { } processId)
        {
            return LocalRpcPeerResolution.Deny(LocalRpcPeerDenial.Unresolved);
        }

        BeforeProcessQuery?.Invoke(processId);
        return QueryWindowsProcess(processId, accepted);
    }

    /// <summary>The Windows process query of a resolution, by the process id the pipe reported (tests query a known process directly).</summary>
    [SupportedOSPlatform("windows")]
    internal static LocalRpcPeerResolution QueryWindowsProcess(int processId, LocalRpcAcceptMoment accepted)
    {
        using var process = LocalRpcWindowsNative.OpenForQuery(processId, out var error);
        if (process is null)
        {
            return LocalRpcPeerResolution.Deny(error == LocalRpcWindowsNative.ErrorInvalidParameter ? LocalRpcPeerDenial.ProcessExited : LocalRpcPeerDenial.Unresolved);
        }

        // Every query below goes through this one handle, so all of them describe the same process object. A process created after the
        // accept cannot be the one that connected: its id was reused after the client exited.
        var running = LocalRpcWindowsNative.IsRunning(process);
        var created = LocalRpcWindowsNative.CreationTimeUtc(process);
        if (running is null || created is null)
        {
            return LocalRpcPeerResolution.Deny(LocalRpcPeerDenial.Unresolved);
        }

        if (running == false || created.Value > accepted.Utc)
        {
            return LocalRpcPeerResolution.Deny(LocalRpcPeerDenial.ProcessExited);
        }

        var sid = LocalRpcWindowsNative.TokenUser(process);
        if (sid is null || CurrentUserSid is not { } own)
        {
            return LocalRpcPeerResolution.Deny(LocalRpcPeerDenial.Unresolved);
        }

        if (!string.Equals(sid, own, StringComparison.OrdinalIgnoreCase))
        {
            return LocalRpcPeerResolution.Deny(LocalRpcPeerDenial.OtherUser);
        }

        var start = new DateTimeOffset(created.Value, TimeSpan.Zero);
        return LocalRpcPeerResolution.Of(new LocalRpcPeer(processId, start, sid, null, LocalRpcWindowsNative.ImagePath(process))
        {
            Process = new LocalRpcProcessIdentity(processId, created.Value.Ticks),
        });
    }

    private LocalRpcPeerResolution ResolveLinux(Socket socket, LocalRpcAcceptMoment accepted)
    {
        // struct ucred { pid_t pid; uid_t uid; gid_t gid; }: the credentials the kernel recorded when the peer connected.
        Span<byte> credentials = stackalloc byte[12];
        int length;
        try
        {
            length = socket.GetRawSocketOption(LocalRpcLinuxProc.SolSocket, LocalRpcLinuxProc.SoPeerCred, credentials);
        }
        catch (SocketException)
        {
            return LocalRpcPeerResolution.Deny(LocalRpcPeerDenial.Unresolved);
        }

        var processId = BinaryPrimitives.ReadInt32LittleEndian(credentials);
        var uid = BinaryPrimitives.ReadUInt32LittleEndian(credentials[4..]);
        if (length != 12 || processId <= 0 || CurrentEffectiveUid is not { } own)
        {
            return LocalRpcPeerResolution.Deny(LocalRpcPeerDenial.Unresolved);
        }

        if (uid != own)
        {
            return LocalRpcPeerResolution.Deny(LocalRpcPeerDenial.OtherUser);
        }

        BeforeProcessQuery?.Invoke(processId);
        return QueryLinuxProcess(processId, uid, accepted);
    }

    /// <summary>The Linux process query of a resolution, by the pid and uid <c>SO_PEERCRED</c> reported (tests query a known process directly).</summary>
    internal static LocalRpcPeerResolution QueryLinuxProcess(int processId, uint uid, LocalRpcAcceptMoment accepted)
    {
        if (!ProcessStart.TryReadLinux(processId, out var start, out var runnable))
        {
            return LocalRpcPeerResolution.Deny(Directory.Exists(LocalRpcLinuxProc.ProcessDirectory(processId))
                ? LocalRpcPeerDenial.Unresolved : LocalRpcPeerDenial.ProcessExited);
        }

        // A process that started after the accept cannot be the one that connected (its id was reused); a zombie has exited.
        var startTicks = start / LocalRpcLinuxProc.TickUnits;
        if (!runnable || (accepted.LinuxUptimeTicks is { } uptime && startTicks > uptime))
        {
            return LocalRpcPeerResolution.Deny(LocalRpcPeerDenial.ProcessExited);
        }

        var executable = LocalRpcLinuxProc.Executable(processId);
        var bootTime = LocalRpcLinuxProc.BootTimeUtc();

        // The same start value again: the id still names the process that was examined.
        if (!ProcessStart.TryReadLinux(processId, out var again, out var stillRunnable) || again != start || !stillRunnable)
        {
            return LocalRpcPeerResolution.Deny(LocalRpcPeerDenial.ProcessExited);
        }

        var started = bootTime is { } boot ? boot + TimeSpan.FromTicks(start) : DateTimeOffset.MinValue;
        return LocalRpcPeerResolution.Of(new LocalRpcPeer(processId, started, null, uid, executable)
        {
            Process = new LocalRpcProcessIdentity(processId, start),
        });
    }

    private static string? ReadCurrentSid()
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        using var identity = WindowsIdentity.GetCurrent();
        return identity.User?.Value;
    }
}

/// <summary>The Linux <c>/proc</c> reads of service mode, without any native binding.</summary>
internal static class LocalRpcLinuxProc
{
    internal const int SolSocket = 1;
    internal const int SoPeerCred = 17;

    /// <summary>100 ns units in one USER_HZ=100 clock tick.</summary>
    internal const long TickUnits = 100_000;

    internal static string ProcessDirectory(int processId) => "/proc/" + processId.ToString(CultureInfo.InvariantCulture);

    /// <summary>The effective uid from the text of <c>/proc/&lt;pid&gt;/status</c> (<c>Uid:</c> real, effective, saved, filesystem).</summary>
    internal static uint? EffectiveUid(string status)
    {
        foreach (var line in status.Split('\n'))
        {
            if (!line.StartsWith("Uid:", StringComparison.Ordinal))
            {
                continue;
            }

            var fields = line["Uid:".Length..].Split(['\t', ' '], StringSplitOptions.RemoveEmptyEntries);
            return fields.Length == 4 && uint.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out var uid) ? uid : null;
        }

        return null;
    }

    /// <summary>The time since boot (CLOCK_BOOTTIME, the clock of a process start in <c>/proc/&lt;pid&gt;/stat</c>) in clock ticks, rounded up.</summary>
    internal static long? UptimeTicks()
    {
        try
        {
            return ParseUptimeTicks(File.ReadAllText("/proc/uptime"));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    internal static long? ParseUptimeTicks(string uptime)
    {
        var first = uptime.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        return first is not null && decimal.TryParse(first, NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out var seconds) && seconds >= 0
            ? (long)Math.Ceiling(seconds * 100m)
            : null;
    }

    /// <summary>The boot time (<c>btime</c> of <c>/proc/stat</c>), or null when it is not readable.</summary>
    internal static DateTimeOffset? BootTimeUtc()
    {
        try
        {
            foreach (var line in File.ReadLines("/proc/stat"))
            {
                if (line.StartsWith("btime ", StringComparison.Ordinal)
                    && long.TryParse(line.AsSpan(6).Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var seconds))
                {
                    return DateTimeOffset.FromUnixTimeSeconds(seconds);
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }

        return null;
    }

    /// <summary>The target of <c>/proc/&lt;pid&gt;/exe</c>, or null when the kernel would not say.</summary>
    internal static string? Executable(int processId)
    {
        try
        {
            return new FileInfo(ProcessDirectory(processId) + "/exe").LinkTarget;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
