// SPDX-License-Identifier: AGPL-3.0-only
using Grpc.Core;

namespace ArcForges.LocalRpc;

/// <summary>What a service-mode handler reads from its call: the connection's peer and, for a stream-lane method, its stream writer.</summary>
public static class LocalRpcServiceCallContextExtensions
{
    /// <summary>
    /// The operating-system identity of the peer of the call's connection, resolved once when the connection was accepted. Null for a
    /// parent-child server, which reads no peer.
    /// </summary>
    public static LocalRpcPeer? GetLocalRpcPeer(this ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var http = context.GetHttpContext();
        return http.Features.Get<ILocalRpcPeerIdentity>()?.Peer;
    }

    /// <summary>
    /// Opens the library's writer over a stream-lane call's response stream (<see cref="LocalRpcServerBuilder.RegisterStream(string, string, LocalRpcStreamProfile)"/>).
    /// It is opened once per call; a method that is not a registered stream-lane method has none.
    /// </summary>
    public static LocalRpcStreamWriter<T> OpenLocalRpcStream<T>(this ServerCallContext context, IServerStreamWriter<T> responseStream)
        where T : class
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(responseStream);
        var call = context.GetHttpContext().Features.Get<LocalRpcStreamCall>()
            ?? throw new InvalidOperationException("Only a method registered with RegisterStream on a service-mode server has a stream-lane writer.");
        if (!call.TryOpenWriter())
        {
            throw new InvalidOperationException("A stream-lane call opens its writer once.");
        }

        return new LocalRpcStreamWriter<T>(call, responseStream, context.Deadline, context.CancellationToken);
    }
}
