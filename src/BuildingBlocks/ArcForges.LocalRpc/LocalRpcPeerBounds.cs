// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.Collections.Frozen;

namespace ArcForges.LocalRpc;

/// <summary>
/// The call bounds of one connected peer: a data lane (active and queued calls in arrival order), the reserved control
/// slots that no data call can take, and the watchdog that closes a connection that never starts a call or sits idle.
/// </summary>
internal sealed class LocalRpcPeerBounds : IDisposable
{
    private readonly LocalRpcBoundsRegistry _registry;
    private readonly object _sync = new();
    private ITimer? _timer;
    private Action? _abort;
    private long _armedAt;
    private TimeSpan _armedFor;
    private int _inFlight;
    private bool _disposed;

    internal LocalRpcPeerBounds(LocalRpcBoundsRegistry registry, string connectionId, LocalRpcPeer? peer = null)
    {
        _registry = registry;
        ConnectionId = connectionId;
        Data = new LocalRpcCallGate(registry.Limits.MaxActiveCalls, registry.Limits.MaxQueuedCalls);
        Control = new LocalRpcCallGate(LocalRpcLimits.ControlSlots, 0);
        Identity = peer is null ? null : new LocalRpcPeerIdentityFeature(peer);
    }

    internal string ConnectionId { get; }

    /// <summary>The service-mode peer of this connection, or null for a parent-child server.</summary>
    internal LocalRpcPeerIdentityFeature? Identity { get; }

    /// <summary>Stream-lane calls this connection holds open now (service mode).</summary>
    internal int StreamsOpen { get; set; }

    internal LocalRpcCallGate Data { get; }

    internal LocalRpcCallGate Control { get; }

    /// <summary>Starts the handshake clock. <paramref name="abort"/> closes the connection when a watchdog limit passes.</summary>
    internal void Start(Action abort)
    {
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }

            _abort = abort;
            _timer = _registry.Time.CreateTimer(OnTimer, null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            Arm(_registry.Limits.HandshakeTimeout);
        }
    }

    /// <summary>A call began (it may still be waiting for a slot): the connection is not idle.</summary>
    internal void CallStarted()
    {
        lock (_sync)
        {
            _inFlight++;
            _ = _timer?.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        }
    }

    /// <summary>A call ended. With none left in flight the idle clock starts.</summary>
    internal void CallFinished()
    {
        lock (_sync)
        {
            _inFlight--;
            if (_inFlight == 0 && !_disposed && _timer is not null)
            {
                Arm(_registry.Limits.IdleTimeout);
            }
        }
    }

    public void Dispose()
    {
        ITimer? timer;
        lock (_sync)
        {
            _disposed = true;
            timer = _timer;
            _timer = null;
            _abort = null;
        }

        timer?.Dispose();
    }

    private void Arm(TimeSpan dueTime)
    {
        _armedAt = _registry.Time.GetTimestamp();
        _armedFor = dueTime;
        _ = _timer!.Change(dueTime, Timeout.InfiniteTimeSpan);
    }

    internal void OnTimer(object? state)
    {
        Action? abort;
        lock (_sync)
        {
            if (_disposed || _inFlight > 0)
            {
                return;
            }

            // A real timer can fire a fraction of a millisecond before the stopwatch says its due time has passed, and a
            // callback queued by an earlier arming can run after a call restarted the clock. Either way the limit is still
            // owed: wait out the remainder instead of dropping it, so a silent peer can never keep its slot.
            var elapsed = _registry.Time.GetElapsedTime(_armedAt);
            if (elapsed < _armedFor)
            {
                _ = _timer?.Change(_armedFor - elapsed, Timeout.InfiniteTimeSpan);
                return;
            }

            abort = _abort;
        }

        abort?.Invoke();
    }
}

/// <summary>The peers of one server and the totals its bounds layer keeps.</summary>
internal sealed class LocalRpcBoundsRegistry
{
    private static readonly LocalRpcControlOperation[] Operations = Enum.GetValues<LocalRpcControlOperation>().Where(operation => operation != LocalRpcControlOperation.None).ToArray();
    private static readonly LocalRpcRefusalReason[] Reasons = Enum.GetValues<LocalRpcRefusalReason>().Where(reason => reason != LocalRpcRefusalReason.None).ToArray();

    private static readonly LocalRpcStreamEndReason[] EndReasons = Enum.GetValues<LocalRpcStreamEndReason>().Where(reason => reason != LocalRpcStreamEndReason.None).ToArray();
    private static readonly LocalRpcPeerDenial[] Denials = Enum.GetValues<LocalRpcPeerDenial>().Where(denial => denial != LocalRpcPeerDenial.None).ToArray();

    private readonly ConcurrentDictionary<string, LocalRpcPeerBounds> _peers = new(StringComparer.Ordinal);
    private readonly long[] _controlAdmitted = new long[Operations.Length + 1];
    private readonly long[] _refused = new long[Reasons.Length + 1];
    private readonly object _streamSync = new();
    private readonly Dictionary<LocalRpcProcessIdentity, int> _processStreams = [];
    private readonly ConcurrentDictionary<LocalRpcStreamCall, byte> _openStreams = new();
    private readonly long[] _streamsEnded = new long[EndReasons.Length + 1];
    private readonly long[] _peersDenied = new long[Denials.Length + 1];
    private long _dataAdmitted;
    private long _streamsAdmitted;
    private long _peersAdmitted;

    internal LocalRpcBoundsRegistry(LocalRpcLimits limits, TimeProvider time)
    {
        Limits = limits;
        Time = time;
    }

    internal LocalRpcLimits Limits { get; }

    internal TimeProvider Time { get; }

    internal LocalRpcPeerBounds Add(string connectionId, LocalRpcPeer? identity = null)
    {
        var peer = new LocalRpcPeerBounds(this, connectionId, identity);
        _peers[connectionId] = peer;
        return peer;
    }

    /// <summary>
    /// Takes a stream-lane slot of the connection and of its client process, or none: the lane never queues. The process is the peer's
    /// process identity, so its streams are counted over every connection it holds to this server.
    /// </summary>
    internal bool TryEnterStream(LocalRpcPeerBounds peer)
    {
        var process = peer.Identity?.Peer.Process;
        lock (_streamSync)
        {
            if (peer.StreamsOpen >= Limits.MaxStreamCallsPerConnection)
            {
                return false;
            }

            var held = process is { } key && _processStreams.TryGetValue(key, out var count) ? count : 0;
            if (held >= Limits.MaxStreamCallsPerProcess)
            {
                return false;
            }

            peer.StreamsOpen++;
            if (process is { } owner)
            {
                _processStreams[owner] = held + 1;
            }
        }

        _ = Interlocked.Increment(ref _streamsAdmitted);
        return true;
    }

    /// <summary>Returns the stream-lane slot <see cref="TryEnterStream"/> took.</summary>
    internal void ExitStream(LocalRpcPeerBounds peer)
    {
        var process = peer.Identity?.Peer.Process;
        lock (_streamSync)
        {
            peer.StreamsOpen--;
            if (process is { } key && _processStreams.TryGetValue(key, out var count))
            {
                if (count <= 1)
                {
                    _ = _processStreams.Remove(key);
                }
                else
                {
                    _processStreams[key] = count - 1;
                }
            }
        }
    }

    internal void StreamOpened(LocalRpcStreamCall call) => _openStreams[call] = 0;

    internal void StreamEnded(LocalRpcStreamCall call, LocalRpcStreamEndReason reason)
    {
        if (_openStreams.TryRemove(call, out _))
        {
            _ = Interlocked.Increment(ref _streamsEnded[(int)(reason == LocalRpcStreamEndReason.None ? LocalRpcStreamEndReason.Cancelled : reason)]);
        }
    }

    internal void CountPeerDecision(LocalRpcPeerDenial denial)
    {
        if (denial == LocalRpcPeerDenial.None)
        {
            _ = Interlocked.Increment(ref _peersAdmitted);
        }
        else
        {
            _ = Interlocked.Increment(ref _peersDenied[(int)denial]);
        }
    }

    internal LocalRpcServiceSnapshot ServiceSnapshot()
    {
        var open = _openStreams.Keys.ToArray();
        var longest = open.Length == 0 ? TimeSpan.Zero : open.Max(call => call.Inactivity);
        return new LocalRpcServiceSnapshot(
            open.Length,
            Interlocked.Read(ref _streamsAdmitted),
            EndReasons.ToFrozenDictionary(reason => reason, reason => Interlocked.Read(ref _streamsEnded[(int)reason])),
            longest,
            Interlocked.Read(ref _peersAdmitted),
            Denials.ToFrozenDictionary(denial => denial, denial => Interlocked.Read(ref _peersDenied[(int)denial])));
    }

    internal void Remove(LocalRpcPeerBounds peer)
    {
        _ = _peers.TryRemove(new KeyValuePair<string, LocalRpcPeerBounds>(peer.ConnectionId, peer));
        peer.Dispose();
    }

    internal bool TryGet(string connectionId, out LocalRpcPeerBounds? peer)
    {
        var found = _peers.TryGetValue(connectionId, out var value);
        peer = value;
        return found;
    }

    internal void CountDataAdmitted() => Interlocked.Increment(ref _dataAdmitted);

    internal void CountControlAdmitted(LocalRpcControlOperation operation) => Interlocked.Increment(ref _controlAdmitted[(int)operation]);

    internal void CountRefused(LocalRpcRefusalReason reason) => Interlocked.Increment(ref _refused[(int)reason]);

    internal LocalRpcBoundsSnapshot Snapshot()
    {
        int peers = 0, dataActive = 0, dataQueued = 0, controlActive = 0;
        foreach (var peer in _peers.Values)
        {
            peers++;
            dataActive += peer.Data.Active;
            dataQueued += peer.Data.Queued;
            controlActive += peer.Control.Active;
        }

        return new LocalRpcBoundsSnapshot(
            peers,
            dataActive,
            dataQueued,
            controlActive,
            Interlocked.Read(ref _dataAdmitted),
            Operations.ToFrozenDictionary(operation => operation, operation => Interlocked.Read(ref _controlAdmitted[(int)operation])),
            Reasons.ToFrozenDictionary(reason => reason, reason => Interlocked.Read(ref _refused[(int)reason])));
    }
}

/// <summary>The connection feature that carries a service-mode peer to every call of its connection.</summary>
internal sealed class LocalRpcPeerIdentityFeature(LocalRpcPeer peer) : ILocalRpcPeerIdentity
{
    public LocalRpcPeer Peer { get; } = peer;
}
