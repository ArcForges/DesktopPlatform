// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Frozen;
using Grpc.Core;

namespace ArcForges.LocalRpc;

/// <summary>Which kind of server a builder makes. The default is the parent-child helper server; nothing changes for it.</summary>
public enum LocalRpcServerMode
{
    /// <summary>A parent serves the helper or extension children it launched (the behaviour of every earlier task).</summary>
    ParentChild = 0,

    /// <summary>
    /// A long-lived per-user service at a well-known endpoint: same-user-only endpoint access, a peer identity for every
    /// connection, the stream lane, raised per-method deadlines and the service connection and idle limits.
    /// </summary>
    Service = 1,
}

/// <summary>Options of a server that are not call bounds.</summary>
public sealed record LocalRpcServerOptions
{
    /// <summary>The server mode; <see cref="LocalRpcServerMode.ParentChild"/> unless the owner asks for a service.</summary>
    public LocalRpcServerMode Mode { get; init; } = LocalRpcServerMode.ParentChild;
}

/// <summary>
/// The deadline profile of one data method (<see cref="LocalRpcServerBuilder.RegisterMethod(string, string, LocalRpcCallProfile)"/>):
/// the deadline a call that declares none gets, and the longest deadline a declared one is shortened to. Time spent waiting for a
/// slot counts, as for every data call.
/// </summary>
/// <param name="DefaultDeadline">The deadline of a call that declares none; positive and at most <paramref name="MaxDeadline"/>.</param>
/// <param name="MaxDeadline">The longest deadline of a call of this method.</param>
public sealed record LocalRpcCallProfile(TimeSpan DefaultDeadline, TimeSpan MaxDeadline)
{
    /// <summary>The longest deadline any profiled method may have in service mode (R-API-006: unary calls at most 120 s).</summary>
    public static readonly TimeSpan LongestServiceDeadline = TimeSpan.FromSeconds(120);
}

/// <summary>
/// The profile of one server-streaming method that runs in the stream lane
/// (<see cref="LocalRpcServerBuilder.RegisterStream(string, string, LocalRpcStreamProfile)"/>). Stream calls are exempt from the data
/// deadline cap and use this profile instead.
/// </summary>
public sealed record LocalRpcStreamProfile
{
    /// <summary>The longest a stream may stay open, or null for no bound. A shorter deadline the client declares still applies.</summary>
    public TimeSpan? MaxLifetime { get; init; }

    /// <summary>
    /// How often the owner sends its own heartbeat frames (15 s by default, R-API-006). The library writes no frame of its own; it only
    /// measures how long a stream has carried no message (<see cref="LocalRpcStreamWriter{T}.Inactivity"/>).
    /// </summary>
    public TimeSpan HeartbeatInterval { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>
    /// The back-pressure bound: messages the owner has written that have not yet reached the transport. One more ends the stream with
    /// <c>RESOURCE_EXHAUSTED</c> (<see cref="LocalRpcStreamEndReason.Overflow"/>), so the owner sends a reset when the client subscribes again.
    /// Default 2,048 (the node's per-subscriber buffer).
    /// </summary>
    public int MaxBufferedMessages { get; init; } = 2048;

    /// <summary>
    /// When set, a message must be taken by the client's reads (the transport accepts it) within this time, or the stream is cancelled
    /// (<see cref="LocalRpcStreamEndReason.ReadsStalled"/>) and its HTTP/2 stream reset. Null (the default) leaves a stalled reader to the
    /// back-pressure bound.
    /// </summary>
    public TimeSpan? RequireReads { get; init; }

    internal LocalRpcStreamProfile Validated()
    {
        if (MaxLifetime is { } lifetime && lifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxLifetime), lifetime, "A stream lifetime is positive or unbounded (null).");
        }

        if (HeartbeatInterval <= TimeSpan.Zero || HeartbeatInterval > TimeSpan.FromMinutes(10))
        {
            throw new ArgumentOutOfRangeException(nameof(HeartbeatInterval), HeartbeatInterval, "The heartbeat interval is positive and at most ten minutes.");
        }

        if (MaxBufferedMessages is < 1 or > 65_536)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxBufferedMessages), MaxBufferedMessages, "The buffered message bound is 1 through 65,536.");
        }

        if (RequireReads is { } reads && (reads <= TimeSpan.Zero || reads > TimeSpan.FromMinutes(10)))
        {
            throw new ArgumentOutOfRangeException(nameof(RequireReads), reads, "The read requirement is positive and at most ten minutes, or null.");
        }

        return this;
    }
}

/// <summary>
/// The operating-system identity of the peer process of one service-mode connection, read once when the connection was accepted and
/// before HTTP/2 read a byte.
/// </summary>
/// <param name="ProcessId">The peer's process id at connect time.</param>
/// <param name="ProcessStartTime">The peer process's start time (UTC).</param>
/// <param name="UserSid">On Windows, the user SID of the peer process token; null elsewhere.</param>
/// <param name="Uid">On Linux, the peer's effective uid from <c>SO_PEERCRED</c>; null elsewhere.</param>
/// <param name="ExecutablePath">The peer's executable, or null when the OS would not say.</param>
public sealed record LocalRpcPeer(int ProcessId, DateTimeOffset ProcessStartTime, string? UserSid, uint? Uid, string? ExecutablePath)
{
    /// <summary>
    /// The peer process in the library's process convention (<see cref="LocalRpcProcessIdentity"/>: on Linux the start in clock ticks
    /// since boot, elsewhere the UTC start time), comparable with <see cref="LocalRpcProcessIdentity.FromProcess"/>.
    /// </summary>
    public LocalRpcProcessIdentity Process { get; init; }
}

/// <summary>
/// The peer identity of a service-mode connection, resolved once per accepted connection before HTTP/2 reads a byte. The connection
/// decision sees it as <see cref="LocalRpcConnectionInfo.Peer"/>; handlers read it with
/// <see cref="LocalRpcServiceCallContextExtensions.GetLocalRpcPeer"/>.
/// </summary>
public interface ILocalRpcPeerIdentity
{
    /// <summary>The peer of the connection.</summary>
    LocalRpcPeer Peer { get; }
}

/// <summary>Why a service-mode connection was dropped before HTTP/2 read a byte.</summary>
public enum LocalRpcPeerDenial
{
    /// <summary>Not denied; never reported.</summary>
    None = 0,

    /// <summary>The OS did not name the peer process or its user (the stream is not a service-mode OS stream, or a query failed).</summary>
    Unresolved = 1,

    /// <summary>The peer process exited (or its id now names a newer process) between accept and query.</summary>
    ProcessExited = 2,

    /// <summary>The peer runs as another user than the server.</summary>
    OtherUser = 3,

    /// <summary>The owner's connection decision refused it, failed or timed out.</summary>
    Refused = 4,
}

/// <summary>How a stream-lane call ended, as the library saw it.</summary>
public enum LocalRpcStreamEndReason
{
    /// <summary>Still open; never reported for an ended stream.</summary>
    None = 0,

    /// <summary>The owner completed the stream and every message reached the transport.</summary>
    Completed = 1,

    /// <summary>The client cancelled, its deadline passed, the connection closed or the server is stopping.</summary>
    Cancelled = 2,

    /// <summary>The profile's <see cref="LocalRpcStreamProfile.MaxLifetime"/> passed (<c>DEADLINE_EXCEEDED</c>).</summary>
    LifetimeEnded = 3,

    /// <summary>More than <see cref="LocalRpcStreamProfile.MaxBufferedMessages"/> waited for the transport (<c>RESOURCE_EXHAUSTED</c>).</summary>
    Overflow = 4,

    /// <summary>The client did not read within <see cref="LocalRpcStreamProfile.RequireReads"/>; the HTTP/2 stream was reset.</summary>
    ReadsStalled = 5,
}

/// <summary>The typed end a stream-lane call reports in its trailers (overflow and lifetime).</summary>
public static class LocalRpcStreamEnd
{
    internal const string Trailer = "x-af-stream-end";

    private static readonly FrozenDictionary<LocalRpcStreamEndReason, string> Names = new Dictionary<LocalRpcStreamEndReason, string>
    {
        [LocalRpcStreamEndReason.Completed] = "completed",
        [LocalRpcStreamEndReason.Cancelled] = "cancelled",
        [LocalRpcStreamEndReason.LifetimeEnded] = "lifetime-ended",
        [LocalRpcStreamEndReason.Overflow] = "overflow",
        [LocalRpcStreamEndReason.ReadsStalled] = "reads-stalled",
    }.ToFrozenDictionary();

    /// <summary>Reads the stream end a server attached to a failed stream call; false when it carries none.</summary>
    public static bool TryRead(RpcException exception, out LocalRpcStreamEndReason reason)
    {
        ArgumentNullException.ThrowIfNull(exception);
        reason = LocalRpcStreamEndReason.None;
        var name = exception.Trailers.GetValue(Trailer);
        if (name is null)
        {
            return false;
        }

        foreach (var (value, text) in Names)
        {
            if (string.Equals(text, name, StringComparison.Ordinal))
            {
                reason = value;
                return true;
            }
        }

        return false;
    }

    internal static string NameOf(LocalRpcStreamEndReason reason) => Names[reason];
}

/// <summary>A point-in-time view of the service-mode additions of one server: the stream lane and the peer decisions.</summary>
/// <param name="StreamsActive">Stream-lane calls open now.</param>
/// <param name="StreamsAdmitted">Stream-lane calls admitted since start.</param>
/// <param name="StreamsEnded">Stream-lane calls ended since start, by reason.</param>
/// <param name="LongestInactivity">The longest time any open stream has carried no message, or zero when none is open.</param>
/// <param name="PeersAdmitted">Connections whose peer was resolved and admitted since start.</param>
/// <param name="PeersDenied">Connections dropped before HTTP/2 read a byte, by reason.</param>
public sealed record LocalRpcServiceSnapshot(
    int StreamsActive,
    long StreamsAdmitted,
    IReadOnlyDictionary<LocalRpcStreamEndReason, long> StreamsEnded,
    TimeSpan LongestInactivity,
    long PeersAdmitted,
    IReadOnlyDictionary<LocalRpcPeerDenial, long> PeersDenied);
