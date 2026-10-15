// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Threading.Channels;
using Grpc.Core;
using Microsoft.AspNetCore.Http;

namespace ArcForges.LocalRpc;

/// <summary>
/// One admitted stream-lane call: its profile, the clock its inactivity is measured on, and how it ended. The admission layer creates it
/// before dispatch and records its end when the handler returns.
/// </summary>
internal sealed class LocalRpcStreamCall
{
    private readonly HttpContext _context;
    private long _lastActivity;
    private int _endReason;
    private int _writerOpened;

    internal LocalRpcStreamCall(LocalRpcStreamProfile profile, TimeProvider time, HttpContext context)
    {
        Profile = profile;
        Time = time;
        _context = context;
        _lastActivity = time.GetTimestamp();
    }

    internal LocalRpcStreamProfile Profile { get; }

    internal TimeProvider Time { get; }

    /// <summary>How long the stream has carried no message (since it opened, or since the last message reached the transport).</summary>
    internal TimeSpan Inactivity => Time.GetElapsedTime(Interlocked.Read(ref _lastActivity));

    internal LocalRpcStreamEndReason EndReason => (LocalRpcStreamEndReason)Volatile.Read(ref _endReason);

    internal void MarkActivity() => Interlocked.Exchange(ref _lastActivity, Time.GetTimestamp());

    /// <summary>Records the first end reason; later ones are ignored.</summary>
    internal bool TryEnd(LocalRpcStreamEndReason reason) =>
        Interlocked.CompareExchange(ref _endReason, (int)reason, (int)LocalRpcStreamEndReason.None) == (int)LocalRpcStreamEndReason.None;

    internal bool TryOpenWriter() => Interlocked.Exchange(ref _writerOpened, 1) == 0;

    /// <summary>Resets the HTTP/2 stream of this call (a reader that does not read never lets trailers through).</summary>
    internal void Abort() => _context.Abort();
}

/// <summary>
/// The writer of one stream-lane call. The owner's handler writes messages without waiting (<see cref="TryWrite"/>); the library moves them
/// to the transport in order and measures how long the stream carries nothing (<see cref="Inactivity"/>; the owner sends its own heartbeat
/// frames every <see cref="LocalRpcStreamProfile.HeartbeatInterval"/>).
/// <list type="bullet">
/// <item>More than <see cref="LocalRpcStreamProfile.MaxBufferedMessages"/> waiting ends the stream with <c>RESOURCE_EXHAUSTED</c> (so the owner sends
/// a reset when the client subscribes again): the waiting messages are dropped, the message already on its way to the transport is kept, and the
/// status follows the data the client has not read yet. A client that does not take that message within the profile's
/// <see cref="LocalRpcStreamProfile.RequireReads"/> (or, without one, its heartbeat interval) is reset instead, because a status cannot pass
/// data that is never read.</item>
/// <item>A client that does not read within <see cref="LocalRpcStreamProfile.RequireReads"/> is reset (<see cref="LocalRpcStreamEndReason.ReadsStalled"/>).</item>
/// </list>
/// A handler opens it once with <see cref="LocalRpcServiceCallContextExtensions.OpenLocalRpcStream"/>, watches <see cref="Ended"/>, and returns
/// through <see cref="CompleteAsync"/>.
/// </summary>
/// <typeparam name="T">The generated response message type.</typeparam>
public sealed class LocalRpcStreamWriter<T> : IAsyncDisposable
    where T : class
{
    private readonly LocalRpcStreamCall _call;
    private readonly IServerStreamWriter<T> _writer;
    private readonly Channel<T> _queue = Channel.CreateUnbounded<T>(new UnboundedChannelOptions { SingleReader = true });
    private readonly CancellationTokenSource _ended;
    private readonly CancellationTokenSource _transport;
    private readonly Task _pump;
    private readonly DateTime _deadline;
    private int _buffered;
    private int _completing;
    private int _disposed;

    internal LocalRpcStreamWriter(LocalRpcStreamCall call, IServerStreamWriter<T> writer, DateTime deadline, CancellationToken callToken)
    {
        _call = call;
        _writer = writer;
        _deadline = deadline;
        _ended = CancellationTokenSource.CreateLinkedTokenSource(callToken);
        _transport = CancellationTokenSource.CreateLinkedTokenSource(callToken);
        _pump = Task.Run(PumpAsync, CancellationToken.None);
    }

    /// <summary>Cancelled when the stream ends for any reason other than the owner completing it: the client, the lifetime, overflow or stalled reads.</summary>
    public CancellationToken Ended => _ended.Token;

    /// <summary>Why the stream ended, or <see cref="LocalRpcStreamEndReason.None"/> while it is open.</summary>
    public LocalRpcStreamEndReason EndReason => _call.EndReason;

    /// <summary>How long the stream has carried no message: since it opened, or since the last message reached the transport.</summary>
    public TimeSpan Inactivity => _call.Inactivity;

    /// <summary>True when the stream has carried no message for longer than its profile's heartbeat interval.</summary>
    public bool HeartbeatOverdue => _call.Inactivity > _call.Profile.HeartbeatInterval;

    /// <summary>Messages written and not yet taken by the transport (the one on its way included).</summary>
    public int Buffered => Volatile.Read(ref _buffered);

    /// <summary>
    /// Queues one message without waiting. False when the stream has ended or is completing; a message over the back-pressure bound is not
    /// queued and ends the stream with <see cref="LocalRpcStreamEndReason.Overflow"/>.
    /// </summary>
    public bool TryWrite(T message)
    {
        ArgumentNullException.ThrowIfNull(message);
        if (_ended.IsCancellationRequested || Volatile.Read(ref _completing) != 0)
        {
            return false;
        }

        if (Interlocked.Increment(ref _buffered) > _call.Profile.MaxBufferedMessages)
        {
            _ = Interlocked.Decrement(ref _buffered);
            End(LocalRpcStreamEndReason.Overflow);
            _ = _queue.Writer.TryComplete();
            return false;
        }

        if (!_queue.Writer.TryWrite(message))
        {
            _ = Interlocked.Decrement(ref _buffered);
            return false;
        }

        return true;
    }

    /// <summary>
    /// Ends the handler's part: waits until every queued message reached the transport, then returns. When the stream ended otherwise, it
    /// throws what the call must answer: <c>RESOURCE_EXHAUSTED</c> for overflow and <c>DEADLINE_EXCEEDED</c> for the lifetime (both with the
    /// <c>x-af-stream-end</c> trailer, <see cref="LocalRpcStreamEnd.TryRead"/>), or an <see cref="OperationCanceledException"/> when the
    /// client went away or did not read.
    /// </summary>
    public async Task CompleteAsync()
    {
        _ = Interlocked.Exchange(ref _completing, 1);
        _ = _queue.Writer.TryComplete();
        if (_call.EndReason == LocalRpcStreamEndReason.Overflow)
        {
            await SettleOverflowAsync().ConfigureAwait(false);
        }
        else
        {
            await _pump.ConfigureAwait(false);
        }

        if (!_ended.IsCancellationRequested && _call.TryEnd(LocalRpcStreamEndReason.Completed))
        {
            return;
        }

        if (_call.EndReason == LocalRpcStreamEndReason.Completed)
        {
            return;
        }

        _ = _call.TryEnd(CancelReason());
        switch (_call.EndReason)
        {
            case LocalRpcStreamEndReason.Overflow:
                throw Failure(StatusCode.ResourceExhausted, "The stream's back-pressure bound was exceeded; subscribe again for a reset.", LocalRpcStreamEndReason.Overflow);
            case LocalRpcStreamEndReason.LifetimeEnded:
                throw Failure(StatusCode.DeadlineExceeded, "The stream's lifetime ended.", LocalRpcStreamEndReason.LifetimeEnded);
            default:
                throw new OperationCanceledException(_ended.Token);
        }
    }

    /// <summary>Ends the stream if the handler left without completing it, and stops moving messages.</summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _ = _queue.Writer.TryComplete();
        if (_call.EndReason == LocalRpcStreamEndReason.None)
        {
            End(LocalRpcStreamEndReason.Cancelled);
        }

        if (_call.EndReason != LocalRpcStreamEndReason.Completed)
        {
            await _transport.CancelAsync().ConfigureAwait(false);
        }

        try
        {
            await _pump.ConfigureAwait(false);
        }
        finally
        {
            _ended.Dispose();
            _transport.Dispose();
        }
    }

    private static RpcException Failure(StatusCode status, string detail, LocalRpcStreamEndReason reason) =>
        new(new Status(status, detail), new Metadata { { LocalRpcStreamEnd.Trailer, LocalRpcStreamEnd.NameOf(reason) } });

    /// <summary>
    /// After an overflow the message on its way stays on its way, so the status can follow it; a client that does not take it within the read
    /// requirement (or the heartbeat interval) never would, and its HTTP/2 stream is reset.
    /// </summary>
    private async Task SettleOverflowAsync()
    {
        try
        {
            await _pump.WaitAsync(_call.Profile.RequireReads ?? _call.Profile.HeartbeatInterval, _call.Time).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            _call.Abort();
            await _transport.CancelAsync().ConfigureAwait(false);
            await _pump.ConfigureAwait(false);
        }
    }

    /// <summary>Why the call's own token ended the stream: its deadline (the profile lifetime or a shorter client deadline) or the client.</summary>
    private LocalRpcStreamEndReason CancelReason() =>
        _deadline != DateTime.MaxValue && DateTime.UtcNow >= _deadline - TimeSpan.FromMilliseconds(50)
            ? LocalRpcStreamEndReason.LifetimeEnded
            : LocalRpcStreamEndReason.Cancelled;

    private void End(LocalRpcStreamEndReason reason)
    {
        _ = _call.TryEnd(reason);
        try
        {
            _ended.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // The stream was disposed meanwhile.
        }
    }

    [SuppressMessage("Design", "CA1031", Justification = "Any transport failure ends the stream; the handler learns it through Ended and CompleteAsync.")]
    private async Task PumpAsync()
    {
        try
        {
            while (await _queue.Reader.WaitToReadAsync(_transport.Token).ConfigureAwait(false))
            {
                // After an overflow the waiting messages are dropped: the client resubscribes and the owner sends a reset.
                while (_call.EndReason != LocalRpcStreamEndReason.Overflow && _queue.Reader.TryRead(out var message))
                {
                    var write = _writer.WriteAsync(message, _transport.Token);
                    if (_call.Profile.RequireReads is { } limit)
                    {
                        try
                        {
                            await write.WaitAsync(limit, _call.Time, _transport.Token).ConfigureAwait(false);
                        }
                        catch (TimeoutException)
                        {
                            // The client has not taken this message within the limit: it is not reading. A status could never pass the
                            // data it does not read, so the HTTP/2 stream is reset.
                            End(LocalRpcStreamEndReason.ReadsStalled);
                            _call.Abort();
                            _ = write.ContinueWith(static task => _ = task.Exception, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default);
                            return;
                        }
                    }
                    else
                    {
                        await write.ConfigureAwait(false);
                    }

                    _ = Interlocked.Decrement(ref _buffered);
                    _call.MarkActivity();
                }

                if (_call.EndReason == LocalRpcStreamEndReason.Overflow)
                {
                    return;
                }
            }
        }
        catch (OperationCanceledException)
        {
            if (_call.EndReason == LocalRpcStreamEndReason.None)
            {
                End(CancelReason());
            }
        }
        catch (Exception)
        {
            End(LocalRpcStreamEndReason.Cancelled);
        }
    }
}
