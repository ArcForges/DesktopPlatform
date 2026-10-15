// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.LocalRpc;

/// <summary>
/// Transport and call bounds of one private helper connection: message size, connections, active and queued calls,
/// the reserved control slots, call deadlines and the handshake and idle limits of a connected peer.
/// </summary>
public sealed record LocalRpcLimits
{
    /// <summary>The ordinary request/response bound of the private helper profile (4 MiB).</summary>
    public const int DefaultMaxMessageBytes = 4 * 1024 * 1024;

    /// <summary>Largest accepted gRPC message in either direction, 1 KiB through 4 MiB.</summary>
    public int MaxMessageBytes { get; init; } = DefaultMaxMessageBytes;

    /// <summary>
    /// Most connections served at once (8; in service mode see <see cref="ServiceDefaults"/>, 64). Further peers wait in the OS backlog and are
    /// accepted as slots free; they are never reset. A parent-child server takes 1 through 64, a service-mode server 1 through 256.
    /// </summary>
    public int MaxConnections { get; init; } = 8;

    /// <summary>The ordinary stream-lane bound of one service-mode connection: stream calls open at once (8).</summary>
    public const int DefaultMaxStreamCallsPerConnection = 8;

    /// <summary>The ordinary stream-lane bound of one client process on one service-mode server, over all its connections (32).</summary>
    public const int DefaultMaxStreamCallsPerProcess = 32;

    /// <summary>The largest service-mode connection bound (256).</summary>
    public const int MaxServiceConnections = 256;

    /// <summary>The service-mode idle close of a connection with no call or stream in flight (10 minutes).</summary>
    public static readonly TimeSpan ServiceIdleTimeout = TimeSpan.FromMinutes(10);

    /// <summary>
    /// The bounds a service-mode server uses when the owner sets none: 64 connections and a 10-minute idle close; every other bound is the
    /// ordinary one (16 active and 64 queued data calls, 2 control slots, 10 s / 30 s data deadlines, 10 s handshake, 8 streams per
    /// connection, 32 per client process). An owner adjusts it with <c>with</c>.
    /// </summary>
    public static LocalRpcLimits ServiceDefaults => new() { MaxConnections = 64, IdleTimeout = ServiceIdleTimeout };

    /// <summary>Stream-lane calls one service-mode connection may hold open at once, 1 through 8. A stream over the bound is refused at once.</summary>
    public int MaxStreamCallsPerConnection { get; init; } = DefaultMaxStreamCallsPerConnection;

    /// <summary>Stream-lane calls one client process may hold open on one service-mode server over all its connections, 1 through 256.</summary>
    public int MaxStreamCallsPerProcess { get; init; } = DefaultMaxStreamCallsPerProcess;

    /// <summary>The ordinary data-call bound of one peer: calls running at once (16).</summary>
    public const int DefaultMaxActiveCalls = 16;

    /// <summary>The ordinary data-call bound of one peer: calls waiting for a slot (64).</summary>
    public const int DefaultMaxQueuedCalls = 64;

    /// <summary>
    /// Control calls (bootstrap, lease renewal, cancellation, health) one peer may run at once. They use their own
    /// slots outside the data budget and never wait: a control call over this number is refused before dispatch.
    /// </summary>
    public const int ControlSlots = 2;

    /// <summary>
    /// Most HTTP/2 streams one connection may hold open: room for 16 active, 64 queued and 2 control calls and, in service mode, 8 stream-lane
    /// calls, plus refusals still draining.
    /// </summary>
    internal const int MaxStreamsPerConnection = 100;

    /// <summary>Request body one waiting call may buffer ahead of dispatch (HTTP/2 stream window; 64 KiB is Kestrel's minimum).</summary>
    internal const int StreamWindowBytes = 64 * 1024;

    /// <summary>
    /// The HTTP/2 connection window. It is flow-control credit, not memory: each stream still buffers at most its own
    /// stream window. Kestrel returns connection credit in steps of half the window once that much has been consumed, so
    /// progress needs a free pool of at least half the window while every other stream's body sits unread: the window is
    /// twice the credit that every stream of the connection can hold unread (stream cap times stream window), and a
    /// further factor of 1.5 is margin. A smaller window let a burst of 80 concurrent calls with 256 KiB bodies leave 16
    /// admitted calls waiting for body credit that never came, with every later call, control calls included, stuck behind them.
    /// </summary>
    internal const int ConnectionWindowBytes = 3 * MaxStreamsPerConnection * StreamWindowBytes;

    /// <summary>Data calls one peer may run at once, 1 through 16. A call over the active and queued bounds is refused before dispatch.</summary>
    public int MaxActiveCalls { get; init; } = DefaultMaxActiveCalls;

    /// <summary>Data calls one peer may have waiting in arrival order, 0 through 64.</summary>
    public int MaxQueuedCalls { get; init; } = DefaultMaxQueuedCalls;

    /// <summary>
    /// Deadline of a data call that declares none (10 s). Time spent waiting for a slot counts against it, and a
    /// declared deadline is never longer than <see cref="MaxCallDeadline"/>.
    /// </summary>
    public TimeSpan DefaultCallDeadline { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>The longest deadline a data call may have (30 s); a longer declared deadline is shortened to it.</summary>
    public TimeSpan MaxCallDeadline { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>The deadline of a control call (5 s): the default when none is declared and the longest allowed.</summary>
    public TimeSpan ControlCallDeadline { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// How long an accepted connection may take to begin its first call (10 s) before it is closed, so a peer that
    /// connects and says nothing, or sends a preface and stalls, cannot hold a connection slot.
    /// </summary>
    public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// How long a connection with no call in flight is kept (60 s, twice the 30 s lease); a live peer renews every 10 s.
    /// </summary>
    public TimeSpan IdleTimeout { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>Longest wait for an OS stream to connect before a client call sees a transport failure.</summary>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Longest time one connection decision may take before the connection is denied.</summary>
    public TimeSpan AuthorizationTimeout { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>Longest wait for in-flight calls to finish when a server stops.</summary>
    public TimeSpan ShutdownTimeout { get; init; } = TimeSpan.FromSeconds(5);

    internal LocalRpcLimits Validated(LocalRpcServerMode mode) =>
        mode == LocalRpcServerMode.Service ? ValidatedForService() : Validated();

    /// <summary>The service-mode bounds: up to 256 connections; every other bound as for a parent-child server.</summary>
    private LocalRpcLimits ValidatedForService()
    {
        if (MaxConnections is < 1 or > MaxServiceConnections)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxConnections), MaxConnections, "The service-mode connection bound is 1 through 256.");
        }

        // Every other bound follows the parent-child rules.
        _ = (this with { MaxConnections = 1 }).Validated();
        return this;
    }

    internal LocalRpcLimits Validated()
    {
        if (MaxMessageBytes is < 1024 or > DefaultMaxMessageBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxMessageBytes), MaxMessageBytes, "The message bound is 1 KiB through 4 MiB.");
        }

        if (MaxConnections is < 1 or > 64)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxConnections), MaxConnections, "The connection bound is 1 through 64.");
        }

        if (MaxStreamCallsPerConnection is < 1 or > DefaultMaxStreamCallsPerConnection)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxStreamCallsPerConnection), MaxStreamCallsPerConnection, "The per-connection stream bound is 1 through 8.");
        }

        if (MaxStreamCallsPerProcess is < 1 or > MaxServiceConnections)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxStreamCallsPerProcess), MaxStreamCallsPerProcess, "The per-process stream bound is 1 through 256.");
        }

        if (ConnectTimeout <= TimeSpan.Zero || ConnectTimeout > TimeSpan.FromMinutes(1))
        {
            throw new ArgumentOutOfRangeException(nameof(ConnectTimeout), ConnectTimeout, "The connect timeout is positive and at most one minute.");
        }

        if (AuthorizationTimeout <= TimeSpan.Zero || AuthorizationTimeout > TimeSpan.FromSeconds(30))
        {
            throw new ArgumentOutOfRangeException(nameof(AuthorizationTimeout), AuthorizationTimeout, "The authorization timeout is positive and at most 30 seconds.");
        }

        if (ShutdownTimeout < TimeSpan.Zero || ShutdownTimeout > TimeSpan.FromMinutes(1))
        {
            throw new ArgumentOutOfRangeException(nameof(ShutdownTimeout), ShutdownTimeout, "The shutdown timeout is zero through one minute.");
        }

        if (MaxActiveCalls is < 1 or > DefaultMaxActiveCalls)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxActiveCalls), MaxActiveCalls, "The active call bound is 1 through 16.");
        }

        if (MaxQueuedCalls is < 0 or > DefaultMaxQueuedCalls)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxQueuedCalls), MaxQueuedCalls, "The queued call bound is 0 through 64.");
        }

        if (MaxCallDeadline <= TimeSpan.Zero || MaxCallDeadline > TimeSpan.FromSeconds(30))
        {
            throw new ArgumentOutOfRangeException(nameof(MaxCallDeadline), MaxCallDeadline, "The longest call deadline is positive and at most 30 seconds.");
        }

        if (DefaultCallDeadline <= TimeSpan.Zero || DefaultCallDeadline > MaxCallDeadline)
        {
            throw new ArgumentOutOfRangeException(nameof(DefaultCallDeadline), DefaultCallDeadline, "The default call deadline is positive and at most the longest call deadline.");
        }

        if (ControlCallDeadline <= TimeSpan.Zero || ControlCallDeadline > TimeSpan.FromSeconds(30))
        {
            throw new ArgumentOutOfRangeException(nameof(ControlCallDeadline), ControlCallDeadline, "The control call deadline is positive and at most 30 seconds.");
        }

        if (HandshakeTimeout <= TimeSpan.Zero || HandshakeTimeout > TimeSpan.FromMinutes(1))
        {
            throw new ArgumentOutOfRangeException(nameof(HandshakeTimeout), HandshakeTimeout, "The handshake timeout is positive and at most one minute.");
        }

        if (IdleTimeout <= TimeSpan.Zero || IdleTimeout > TimeSpan.FromMinutes(10))
        {
            throw new ArgumentOutOfRangeException(nameof(IdleTimeout), IdleTimeout, "The idle timeout is positive and at most ten minutes.");
        }

        return this;
    }
}
