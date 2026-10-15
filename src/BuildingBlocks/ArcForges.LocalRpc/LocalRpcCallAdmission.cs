// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using Grpc.AspNetCore.Server;
using Grpc.Core;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace ArcForges.LocalRpc;

/// <summary>
/// Decides, for every routed gRPC call and before any service code or body read, whether the call may run. A data call
/// takes one of the peer's active slots or waits in arrival order in the bounded queue; a control call takes one of
/// the two reserved slots that no data call can use and never waits; anything else is refused with a typed status.
/// The remaining deadline is handed to the gRPC server, so the time spent waiting counts against it.
/// </summary>
internal sealed class LocalRpcCallAdmission
{
    private const string TimeoutHeader = "grpc-timeout";
    private const long MaxTimeoutDigits = 99_999_999;

    private static readonly IReadOnlyDictionary<string, LocalRpcCallProfile> NoProfiles = new Dictionary<string, LocalRpcCallProfile>();
    private static readonly IReadOnlyDictionary<string, LocalRpcStreamProfile> NoStreams = new Dictionary<string, LocalRpcStreamProfile>();

    private readonly LocalRpcBoundsRegistry _registry;
    private readonly IReadOnlyDictionary<string, LocalRpcControlOperation> _control;
    private readonly IReadOnlyDictionary<string, LocalRpcCallProfile> _profiles;
    private readonly IReadOnlyDictionary<string, LocalRpcStreamProfile> _streams;

    internal LocalRpcCallAdmission(LocalRpcBoundsRegistry registry, IReadOnlyDictionary<string, LocalRpcControlOperation> control)
        : this(registry, control, NoProfiles, NoStreams)
    {
    }

    internal LocalRpcCallAdmission(
        LocalRpcBoundsRegistry registry,
        IReadOnlyDictionary<string, LocalRpcControlOperation> control,
        IReadOnlyDictionary<string, LocalRpcCallProfile> profiles,
        IReadOnlyDictionary<string, LocalRpcStreamProfile> streams)
    {
        _registry = registry;
        _control = control;
        _profiles = profiles;
        _streams = streams;
    }

    internal async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var metadata = context.GetEndpoint()?.Metadata.GetMetadata<GrpcMethodMetadata>();
        if (metadata is null)
        {
            // Not a registered gRPC method (an unknown service is answered UNIMPLEMENTED by the router's own endpoint).
            await next(context).ConfigureAwait(false);
            return;
        }

        if (!_registry.TryGet(context.Connection.Id, out var peer) || peer is null)
        {
            Answer(context, StatusCode.Internal, "The connection is not tracked.", reason: null);
            return;
        }

        if (peer.Identity is { } identity)
        {
            context.Features.Set<ILocalRpcPeerIdentity>(identity);
        }

        var limits = _registry.Limits;
        var key = metadata.Method.ServiceName + "/" + metadata.Method.Name;
        var nested = context.Request.Headers.TryGetValue(LocalRpcRefusal.NestedHeader, out var marker) && marker.Count == 1 && marker[0] == "1";
        if (_streams.TryGetValue(key, out var stream))
        {
            await InvokeStreamAsync(context, next, peer, stream, nested).ConfigureAwait(false);
            return;
        }

        var isControl = _control.TryGetValue(key, out var operation);
        var window = !isControl && _profiles.TryGetValue(key, out var profile)
            ? DeadlineWindow(context, profile.DefaultDeadline, profile.MaxDeadline)
            : DeadlineWindow(context, limits, isControl);
        var gate = isControl ? peer.Control : peer.Data;
        var started = _registry.Time.GetTimestamp();
        var admitted = false;
        peer.CallStarted();
        try
        {
            LocalRpcGateOutcome outcome;
            try
            {
                // The deadline clock covers the wait only: once a slot is held the gRPC server enforces the remaining time.
                using var deadline = new CancellationTokenSource(window, _registry.Time);
                using var waiting = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token, context.RequestAborted);
                outcome = await gate.EnterAsync(mayQueue: !isControl && !nested, waiting.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                if (!context.RequestAborted.IsCancellationRequested)
                {
                    Refuse(context, LocalRpcRefusalReason.DeadlineBeforeDispatch);
                }

                return;
            }

            if (outcome == LocalRpcGateOutcome.Refused)
            {
                Refuse(context, isControl ? LocalRpcRefusalReason.ControlBusy
                    : nested ? LocalRpcRefusalReason.CallbackNotQueued : LocalRpcRefusalReason.DataQueueFull);
                return;
            }

            admitted = true;
            var remaining = window - _registry.Time.GetElapsedTime(started);
            if (remaining <= TimeSpan.Zero)
            {
                Refuse(context, LocalRpcRefusalReason.DeadlineBeforeDispatch);
                return;
            }

            if (isControl)
            {
                _registry.CountControlAdmitted(operation);
            }
            else
            {
                _registry.CountDataAdmitted();
            }

            context.Request.Headers[TimeoutHeader] = ToTimeoutHeader(remaining);
            using (LocalRpcCallbackGuard.Enter(nested ? 1 : 0))
            {
                await next(context).ConfigureAwait(false);
            }
        }
        finally
        {
            if (admitted)
            {
                gate.Exit();
            }

            peer.CallFinished();
        }
    }

    /// <summary>The time a call may take from now: its declared deadline or the lane default, never above the lane maximum.</summary>
    internal static TimeSpan DeadlineWindow(HttpContext context, LocalRpcLimits limits, bool isControl) =>
        DeadlineWindow(
            context,
            isControl ? limits.ControlCallDeadline : limits.DefaultCallDeadline,
            isControl ? limits.ControlCallDeadline : limits.MaxCallDeadline);

    /// <summary>The time a call may take from now: its declared deadline or <paramref name="fallback"/>, never above <paramref name="maximum"/>.</summary>
    internal static TimeSpan DeadlineWindow(HttpContext context, TimeSpan fallback, TimeSpan maximum)
    {
        if (context.Request.Headers.TryGetValue(TimeoutHeader, out var values) && values.Count == 1
            && TryParseTimeout(values[0], out var declared))
        {
            return declared < maximum ? declared : maximum;
        }

        return fallback;
    }

    /// <summary>
    /// The deadline of a stream-lane call: the shorter of the client's declared deadline and the profile's lifetime, or none when neither
    /// bounds it. The data deadline cap does not apply.
    /// </summary>
    internal static TimeSpan? StreamWindow(HttpContext context, LocalRpcStreamProfile profile)
    {
        TimeSpan? declared = context.Request.Headers.TryGetValue(TimeoutHeader, out var values) && values.Count == 1
            && TryParseTimeout(values[0], out var parsed) ? parsed : null;
        return (declared, profile.MaxLifetime) switch
        {
            ({ } client, { } lifetime) => client < lifetime ? client : lifetime,
            ({ } client, null) => client,
            (null, { } lifetime) => lifetime,
            _ => null,
        };
    }

    /// <summary>
    /// A stream-lane call: it never waits and never takes a data or control slot. It is refused at once when its connection or its client
    /// process holds the bound of open streams; otherwise its deadline is its profile's, and the connection is never idle while it is open.
    /// </summary>
    private async Task InvokeStreamAsync(HttpContext context, RequestDelegate next, LocalRpcPeerBounds peer, LocalRpcStreamProfile profile, bool nested)
    {
        var entered = false;
        LocalRpcStreamCall? call = null;
        var started = _registry.Time.GetTimestamp();
        var window = StreamWindow(context, profile);
        peer.CallStarted();
        try
        {
            if (!_registry.TryEnterStream(peer))
            {
                Refuse(context, LocalRpcRefusalReason.StreamLaneFull);
                return;
            }

            entered = true;
            if (window is { } bounded)
            {
                context.Request.Headers[TimeoutHeader] = ToTimeoutHeader(bounded);
            }
            else
            {
                _ = context.Request.Headers.Remove(TimeoutHeader);
            }

            call = new LocalRpcStreamCall(profile, _registry.Time, context);
            context.Features.Set(call);
            _registry.StreamOpened(call);
            using (LocalRpcCallbackGuard.Enter(nested ? 1 : 0))
            {
                await next(context).ConfigureAwait(false);
            }

            _ = call.TryEnd(
                window is { } lifetime && _registry.Time.GetElapsedTime(started) >= lifetime - TimeSpan.FromMilliseconds(50) ? LocalRpcStreamEndReason.LifetimeEnded
                : context.RequestAborted.IsCancellationRequested ? LocalRpcStreamEndReason.Cancelled
                : LocalRpcStreamEndReason.Completed);
        }
        finally
        {
            if (call is not null)
            {
                _ = call.TryEnd(LocalRpcStreamEndReason.Cancelled);
                _registry.StreamEnded(call, call.EndReason);
            }

            if (entered)
            {
                _registry.ExitStream(peer);
            }

            peer.CallFinished();
        }
    }

    /// <summary>Parses a gRPC timeout (up to eight digits and one of H, M, S, m, u, n).</summary>
    internal static bool TryParseTimeout(string? text, out TimeSpan timeout)
    {
        timeout = default;
        if (string.IsNullOrEmpty(text) || text.Length < 2 || text.Length > 9)
        {
            return false;
        }

        var digits = text.AsSpan(0, text.Length - 1);
        foreach (var digit in digits)
        {
            if (digit is < '0' or > '9')
            {
                return false;
            }
        }

        var value = long.Parse(digits, NumberStyles.None, CultureInfo.InvariantCulture);
        var ticks = text[^1] switch
        {
            'H' => value * TimeSpan.TicksPerHour,
            'M' => value * TimeSpan.TicksPerMinute,
            'S' => value * TimeSpan.TicksPerSecond,
            'm' => value * TimeSpan.TicksPerMillisecond,
            'u' => value * (TimeSpan.TicksPerMillisecond / 1000),
            'n' => value / 100,
            _ => -1L,
        };
        if (ticks < 0)
        {
            return false;
        }

        timeout = TimeSpan.FromTicks(ticks);
        return true;
    }

    internal static string ToTimeoutHeader(TimeSpan remaining)
    {
        var milliseconds = (long)Math.Ceiling(remaining.TotalMilliseconds);
        return Math.Clamp(milliseconds, 1, MaxTimeoutDigits).ToString(CultureInfo.InvariantCulture) + "m";
    }

    private void Refuse(HttpContext context, LocalRpcRefusalReason reason)
    {
        _registry.CountRefused(reason);
        Answer(context, LocalRpcRefusal.StatusOf(reason), "The call was refused before dispatch: " + LocalRpcRefusal.NameOf(reason) + ".", reason);
    }

    private static void Answer(HttpContext context, StatusCode status, string message, LocalRpcRefusalReason? reason)
    {
        if (context.Response.HasStarted)
        {
            return;
        }

        var response = context.Response;
        response.StatusCode = StatusCodes.Status200OK;
        response.ContentType = "application/grpc";
        response.Headers["grpc-status"] = ((int)status).ToString(CultureInfo.InvariantCulture);
        response.Headers["grpc-message"] = message;
        if (reason is { } known)
        {
            response.Headers[LocalRpcRefusal.ReasonTrailer] = LocalRpcRefusal.NameOf(known);
            response.Headers[LocalRpcRefusal.DispatchedTrailer] = "0";
        }
    }
}
