// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;
using Grpc.AspNetCore.Server;
using Grpc.Core;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace ArcForges.LocalRpc;

/// <summary>
/// Collects the explicit registration of a private helper server. Nothing is discovered by scanning: a service
/// is served only when its generated base class implementation is added here.
/// </summary>
public sealed class LocalRpcServerBuilder
{
    private const DynamicallyAccessedMemberTypes ServiceMembers =
        DynamicallyAccessedMemberTypes.PublicConstructors | DynamicallyAccessedMemberTypes.PublicMethods
        | DynamicallyAccessedMemberTypes.NonPublicMethods;

    private readonly LocalRpcEndpoint? _endpoint;
    private readonly LocalRpcStreamSupplier? _supplier;
    private readonly List<ServiceRegistration> _services = [];
    private readonly HashSet<Type> _registered = [];
    private readonly Dictionary<string, LocalRpcControlOperation> _control = new(StringComparer.Ordinal);
    private readonly Dictionary<string, LocalRpcCallProfile> _profiles = new(StringComparer.Ordinal);
    private readonly Dictionary<string, LocalRpcStreamProfile> _streams = new(StringComparer.Ordinal);
    private LocalRpcServerOptions _options = new();
    private bool _limitsSet;
    private LocalRpcPeerResolver? _peerResolver;
    private TimeProvider _time = TimeProvider.System;
    private Action<IServiceCollection>? _hostServices;
    private Func<IEnumerable<string>?, IEnumerable<string>?>? _addressView;
    private LocalRpcLimits _limits = new();
    private Func<LocalRpcConnectionInfo, CancellationToken, ValueTask<bool>>? _authorizer;
    private LocalRpcRegistration? _registration;
    private LocalRpcChildDeclaration? _declaration;
    private bool _built;

    internal LocalRpcServerBuilder(LocalRpcEndpoint? endpoint, LocalRpcStreamSupplier? supplier)
    {
        _endpoint = endpoint;
        _supplier = supplier;
    }

    /// <summary>
    /// Transport bounds; validated when the server is built. A service-mode server whose owner sets none uses
    /// <see cref="LocalRpcLimits.ServiceDefaults"/>.
    /// </summary>
    public LocalRpcLimits Limits
    {
        get => _limits;
        set
        {
            _limits = value ?? throw new ArgumentNullException(nameof(value));
            _limitsSet = true;
        }
    }

    /// <summary>
    /// The server options. <see cref="LocalRpcServerMode.Service"/> makes a long-lived per-user service at the builder's well-known endpoint:
    /// the endpoint is created same-user-only, every connection's peer is resolved and checked before HTTP/2 reads a byte, and the stream lane,
    /// raised method deadlines and the service connection and idle limits apply. The default parent-child server is unchanged.
    /// </summary>
    public LocalRpcServerOptions Options
    {
        get => _options;
        set => _options = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>Serves one generated gRPC service implementation. Each service type is registered at most once.</summary>
    public LocalRpcServerBuilder AddService<[DynamicallyAccessedMembers(ServiceMembers)] TService>(TService service)
        where TService : class
    {
        ArgumentNullException.ThrowIfNull(service);
        EnsureNotBuilt();
        if (!_registered.Add(typeof(TService)))
        {
            throw new InvalidOperationException("A service type is registered once.");
        }

        _services.Add(new ServiceRegistration(
            services => services.AddSingleton(service),
            endpoints => endpoints.MapGrpcService<TService>()));
        return this;
    }

    /// <summary>
    /// Decides for every accepted connection, before HTTP/2 reads a byte, whether the peer may talk to this server.
    /// A decision that throws denies the connection.
    /// </summary>
    public LocalRpcServerBuilder AuthorizeConnections(Func<LocalRpcConnectionInfo, bool> authorizer)
    {
        ArgumentNullException.ThrowIfNull(authorizer);
        EnsureNotBuilt();
        _authorizer = (connection, _) => ValueTask.FromResult(authorizer(connection));
        return this;
    }

    /// <summary>
    /// Decides asynchronously for every accepted connection, before HTTP/2 reads a byte. The decision receives a token that
    /// is cancelled after <see cref="LocalRpcLimits.AuthorizationTimeout"/> and when the server stops; a decision that throws, times out or
    /// is cancelled denies the connection. This replaces any earlier decision set on the builder.
    /// </summary>
    public LocalRpcServerBuilder AuthorizeConnectionsAsync(Func<LocalRpcConnectionInfo, CancellationToken, ValueTask<bool>> authorizer)
    {
        ArgumentNullException.ThrowIfNull(authorizer);
        EnsureNotBuilt();
        _authorizer = authorizer;
        return this;
    }

    /// <summary>
    /// Declares that one method of a registered service is a control operation. Control calls run in the peer's two
    /// reserved slots, outside the data budget, so a saturated data lane cannot starve bootstrap, lease renewal,
    /// cancellation or health. Every other method is a data call. A method that no registered service serves makes
    /// <see cref="LocalRpcServer.StartAsync"/> fail.
    /// </summary>
    /// <param name="operation">The control operation the method performs.</param>
    /// <param name="serviceName">The full protobuf service name, for example <c>arcforges.local.platform.v1.LocalBootstrapService</c>.</param>
    /// <param name="methodName">The method name within the service.</param>
    public LocalRpcServerBuilder RegisterControl(LocalRpcControlOperation operation, string serviceName, string methodName)
    {
        if (operation == LocalRpcControlOperation.None || !Enum.IsDefined(operation))
        {
            throw new ArgumentOutOfRangeException(nameof(operation), operation, "Unknown control operation.");
        }

        ArgumentNullException.ThrowIfNull(serviceName);
        ArgumentNullException.ThrowIfNull(methodName);
        EnsureNotBuilt();
        if (!IsProtoName(serviceName) || !IsProtoName(methodName) || methodName.Contains('.', StringComparison.Ordinal))
        {
            throw new ArgumentException("A control method is a protobuf service name and a method name.");
        }

        if (_profiles.ContainsKey(serviceName + "/" + methodName) || _streams.ContainsKey(serviceName + "/" + methodName))
        {
            throw new InvalidOperationException("A method has one lane and one profile.");
        }

        if (!_control.TryAdd(serviceName + "/" + methodName, operation))
        {
            throw new InvalidOperationException("A control method is registered once.");
        }

        return this;
    }

    /// <summary>Declares a generated method as a control operation (see <see cref="RegisterControl(LocalRpcControlOperation, string, string)"/>).</summary>
    public LocalRpcServerBuilder RegisterControl(LocalRpcControlOperation operation, IMethod method)
    {
        ArgumentNullException.ThrowIfNull(method);
        return RegisterControl(operation, method.ServiceName, method.Name);
    }

    /// <summary>
    /// Sets the deadline profile of one data method (AD-0013 refactor §1.2.3): a call that declares no deadline gets
    /// <see cref="LocalRpcCallProfile.DefaultDeadline"/>, and a declared one is shortened to <see cref="LocalRpcCallProfile.MaxDeadline"/>.
    /// Methods without a profile keep the server's data deadlines (10 s / 30 s). A parent-child server's profile may only lower them; a
    /// service-mode server's may raise the deadline up to <see cref="LocalRpcCallProfile.LongestServiceDeadline"/> (120 s). A method that no
    /// registered service serves makes <see cref="LocalRpcServer.StartAsync"/> fail.
    /// </summary>
    /// <param name="serviceName">The full protobuf service name.</param>
    /// <param name="methodName">The method name within the service.</param>
    /// <param name="profile">The method's deadlines.</param>
    public LocalRpcServerBuilder RegisterMethod(string serviceName, string methodName, LocalRpcCallProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var key = MethodKey(serviceName, methodName);
        if (profile.DefaultDeadline <= TimeSpan.Zero || profile.MaxDeadline < profile.DefaultDeadline
            || profile.MaxDeadline > LocalRpcCallProfile.LongestServiceDeadline)
        {
            throw new ArgumentOutOfRangeException(nameof(profile), profile, "A call profile's default deadline is positive and at most its maximum, which is at most 120 seconds.");
        }

        if (_control.ContainsKey(key) || _streams.ContainsKey(key) || !_profiles.TryAdd(key, profile))
        {
            throw new InvalidOperationException("A method has one lane and one profile.");
        }

        return this;
    }

    /// <summary>Sets the deadline profile of a generated method (see <see cref="RegisterMethod(string, string, LocalRpcCallProfile)"/>).</summary>
    public LocalRpcServerBuilder RegisterMethod(IMethod method, LocalRpcCallProfile profile)
    {
        ArgumentNullException.ThrowIfNull(method);
        return RegisterMethod(method.ServiceName, method.Name, profile);
    }

    /// <summary>
    /// Runs one server-streaming method in the stream lane of a service-mode server (AD-0013 refactor §1.2.2): separate from the data and
    /// control lanes, at most <see cref="LocalRpcLimits.MaxStreamCallsPerConnection"/> per connection and
    /// <see cref="LocalRpcLimits.MaxStreamCallsPerProcess"/> per client process, never queued, exempt from the data deadline cap and held to
    /// <paramref name="profile"/>. Its handler writes through <see cref="LocalRpcServiceCallContextExtensions.OpenLocalRpcStream"/>.
    /// <see cref="LocalRpcServer.StartAsync"/> fails when no registered service serves the method as a server-streaming method, and
    /// <see cref="Build"/> fails for a parent-child server, whose streams stay data calls.
    /// </summary>
    public LocalRpcServerBuilder RegisterStream(string serviceName, string methodName, LocalRpcStreamProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var key = MethodKey(serviceName, methodName);
        _ = profile.Validated();
        if (_control.ContainsKey(key) || _profiles.ContainsKey(key) || !_streams.TryAdd(key, profile))
        {
            throw new InvalidOperationException("A method has one lane and one profile.");
        }

        return this;
    }

    /// <summary>Runs a generated server-streaming method in the stream lane (see <see cref="RegisterStream(string, string, LocalRpcStreamProfile)"/>).</summary>
    public LocalRpcServerBuilder RegisterStream(IMethod method, LocalRpcStreamProfile profile)
    {
        ArgumentNullException.ThrowIfNull(method);
        if (method.Type != MethodType.ServerStreaming)
        {
            throw new ArgumentException("The stream lane runs server-streaming methods.", nameof(method));
        }

        return RegisterStream(method.ServiceName, method.Name, profile);
    }

    /// <summary>Test seam: resolves service-mode peers with <paramref name="resolver"/> instead of the OS (offline tests over supplied streams).</summary>
    internal LocalRpcServerBuilder UsePeerResolver(LocalRpcPeerResolver resolver)
    {
        EnsureNotBuilt();
        _peerResolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        return this;
    }

    private string MethodKey(string serviceName, string methodName)
    {
        ArgumentNullException.ThrowIfNull(serviceName);
        ArgumentNullException.ThrowIfNull(methodName);
        EnsureNotBuilt();
        if (!IsProtoName(serviceName) || !IsProtoName(methodName) || methodName.Contains('.', StringComparison.Ordinal))
        {
            throw new ArgumentException("A method is a protobuf service name and a method name.");
        }

        return serviceName + "/" + methodName;
    }

    /// <summary>Test seam: the clock that drives queue deadlines and the handshake and idle limits.</summary>
    internal LocalRpcServerBuilder UseTimeProvider(TimeProvider time)
    {
        EnsureNotBuilt();
        _time = time ?? throw new ArgumentNullException(nameof(time));
        return this;
    }

    /// <summary>Test seam: alters the addresses the host reports once started, to prove the post-start address guard refuses an IP.</summary>
    internal LocalRpcServerBuilder ViewReportedAddresses(Func<IEnumerable<string>?, IEnumerable<string>?> view)
    {
        EnsureNotBuilt();
        _addressView = view ?? throw new ArgumentNullException(nameof(view));
        return this;
    }

    /// <summary>Test seam: adds services to the host after the profile, to prove the start-up guards refuse them.</summary>
    internal LocalRpcServerBuilder ConfigureHostServices(Action<IServiceCollection> configure)
    {
        EnsureNotBuilt();
        _hostServices = configure ?? throw new ArgumentNullException(nameof(configure));
        return this;
    }

    /// <summary>A protobuf name: dot-separated identifiers of ASCII letters, digits and underscores that do not start with a digit.</summary>
    internal static bool IsProtoName(string name)
    {
        if (name.Length == 0)
        {
            return false;
        }

        var segmentStart = true;
        foreach (var character in name)
        {
            if (character == '.')
            {
                if (segmentStart)
                {
                    return false;
                }

                segmentStart = true;
                continue;
            }

            var letter = character is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or '_';
            var digit = character is >= '0' and <= '9';
            if (!(letter || (digit && !segmentStart)))
            {
                return false;
            }

            segmentStart = false;
        }

        return !segmentStart;
    }

    /// <summary>
    /// Serves one child's registration (WP-08.02). Every call is checked before routing: only the two bootstrap steps of an
    /// unregistered child pass without credentials, every other call must present the registered peer nonce, caller instance and
    /// contract-set digest on the registered connection within the lease, and a registered child is admitted no second connection.
    /// The owner still registers its generated LocalBootstrap service, which maps its messages onto
    /// <see cref="LocalRpcServerCallContextExtensions.GetBootstrapCall"/>. A registration serves one server.
    /// </summary>
    public LocalRpcServerBuilder RequireRegistration(LocalRpcRegistration registration)
    {
        ArgumentNullException.ThrowIfNull(registration);
        EnsureNotBuilt();
        if (_registration is not null)
        {
            throw new InvalidOperationException("A server serves one registration.");
        }

        _registration = registration;
        return this;
    }

    /// <summary>
    /// Fixes the closed set of generated services this server serves (WP-08.03). <see cref="LocalRpcServer.StartAsync"/> fails, and
    /// nothing listens, unless the services registered with <see cref="AddService{TService}"/> are exactly the declared ones: a served service
    /// that was not declared and a declared service that is not served are both refused, so a service cannot appear by being added
    /// and no declared service can be missing. When a registration is required the declaration must be for the launch's child kind, and
    /// it must name the LocalBootstrap service the registration is served through.
    /// </summary>
    public LocalRpcServerBuilder RequireDeclaredServices(LocalRpcChildDeclaration declaration)
    {
        ArgumentNullException.ThrowIfNull(declaration);
        EnsureNotBuilt();
        if (_declaration is not null)
        {
            throw new InvalidOperationException("A server has one service declaration.");
        }

        _declaration = declaration;
        return this;
    }

    /// <summary>Builds the server. Nothing listens until <see cref="LocalRpcServer.StartAsync"/>.</summary>
    public LocalRpcServer Build()
    {
        EnsureNotBuilt();
        var mode = _options.Mode;
        if (!Enum.IsDefined(mode))
        {
            throw new InvalidOperationException("Unknown server mode.");
        }

        var service = mode == LocalRpcServerMode.Service;
        var limits = (service && !_limitsSet ? LocalRpcLimits.ServiceDefaults : _limits).Validated(mode);
        if (_services.Count == 0)
        {
            throw new InvalidOperationException("A server registers at least one generated service explicitly.");
        }

        ValidateServiceMode(service, limits);

        var required = _registration;
        if (required is not null && _declaration is { } declared && declared.ChildKind != required.Launch.Descriptor.Identity.ChildKind)
        {
            throw new InvalidOperationException("The service declaration is for another child kind than the registration's launch.");
        }

        if (required is not null)
        {
            // The bootstrap steps and the lease renewal must run in the reserved control slots, or a saturated data lane would starve
            // a child's registration and its renewals. Declaring them also makes StartAsync fail if no LocalBootstrap service is served.
            DeclareRegistrationControl(LocalRpcRegistration.ChallengePath, LocalRpcControlOperation.Bootstrap);
            DeclareRegistrationControl(LocalRpcRegistration.ConfirmPath, LocalRpcControlOperation.Bootstrap);
            DeclareRegistrationControl(LocalRpcRegistration.RenewPath, LocalRpcControlOperation.LeaseRenewal);
        }

        if (_supplier is not null)
        {
            _supplier.Claim();
        }

        required?.BindToServer();
        _built = true;
        var bounds = new LocalRpcBoundsRegistry(limits, _time);
        var resolver = service ? _peerResolver ?? new LocalRpcOsPeerResolver() : null;
        var endPoint = new LocalRpcListenEndPoint(_endpoint, _supplier, limits, required is null ? _authorizer : WithRegistration(required, _authorizer), bounds, resolver);
        var registrations = _services.ToArray();
        var control = _control.ToFrozenDictionary(StringComparer.Ordinal);
        var profiles = _profiles.ToFrozenDictionary(StringComparer.Ordinal);
        var streams = _streams.ToFrozenDictionary(StringComparer.Ordinal);
        var admission = new LocalRpcCallAdmission(bounds, control, profiles, streams);
        var hostServices = _hostServices;
        var addressView = _addressView;
        var routes = new RouteCapture();
        var host = new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseKestrelCore();
                web.ConfigureKestrel(kestrel =>
                {
                    kestrel.AddServerHeader = false;
                    kestrel.Limits.MaxConcurrentUpgradedConnections = 0;
                    kestrel.Limits.MaxRequestBodySize = null;
                    kestrel.Limits.MaxRequestHeadersTotalSize = 32 * 1024;
                    kestrel.Limits.Http2.MaxRequestHeaderFieldSize = 16 * 1024;
                    // The call bounds need room to answer excess calls with a typed refusal instead of an HTTP/2 stream
                    // refusal (16 active + 64 queued + 2 control fit under the stream cap), and the flow-control windows
                    // are pinned so a queued call never buffers more than its stream window and a peer never more than the
                    // connection window of request body ahead of dispatch.
                    kestrel.Limits.Http2.MaxStreamsPerConnection = LocalRpcLimits.MaxStreamsPerConnection;
                    kestrel.Limits.Http2.InitialConnectionWindowSize = LocalRpcLimits.ConnectionWindowBytes;
                    kestrel.Limits.Http2.InitialStreamWindowSize = LocalRpcLimits.StreamWindowBytes;
                    if (service)
                    {
                        // The connection idle rule is the library's (10 minutes, never while a stream is open); Kestrel's own keep-alive close
                        // of a connection without active streams (130 s by default) must not end it first.
                        kestrel.Limits.KeepAliveTimeout = limits.IdleTimeout + TimeSpan.FromMinutes(1);
                    }

                    kestrel.Listen(endPoint, listen => listen.Protocols = HttpProtocols.Http2);
                });
                web.ConfigureServices(services =>
                {
                    services.RemoveAll<IConnectionListenerFactory>();
                    services.AddSingleton<IConnectionListenerFactory, LocalRpcConnectionListenerFactory>();
                    services.AddSingleton<IHostLifetime, InertHostLifetime>();
                    services.Configure<HostOptions>(options => options.ShutdownTimeout = limits.ShutdownTimeout);
                    services.AddRouting();
                    services.AddGrpc();
                    // AddGrpc registers its own defaults (including gzip) after a caller's configure delegate, so the
                    // profile is applied as a post-configuration; the compression guard below does not depend on it.
                    services.PostConfigure<GrpcServiceOptions>(options =>
                    {
                        options.MaxReceiveMessageSize = limits.MaxMessageBytes;
                        options.MaxSendMessageSize = limits.MaxMessageBytes;
                        options.EnableDetailedErrors = false;
                        options.IgnoreUnknownServices = false;
                        options.ResponseCompressionAlgorithm = null;
                        options.CompressionProviders.Clear();
                    });
                    foreach (var registration in registrations)
                    {
                        registration.Register(services);
                    }

                    hostServices?.Invoke(services);
                });
                web.Configure(app =>
                {
                    app.Use(RefuseCompressedRequestsAsync);
                    if (required is not null)
                    {
                        app.Use(LocalRpcRegistrationGate.Create(required));
                    }

                    app.UseRouting();
                    app.Use(admission.InvokeAsync);
                    app.UseEndpoints(endpoints =>
                    {
                        routes.Builder = endpoints;
                        foreach (var registration in registrations)
                        {
                            registration.Map(endpoints);
                        }
                    });
                });
            })
            .Build();
        return new LocalRpcServer(host, limits, _supplier, bounds, control, routes, addressView, _declaration)
        {
            Profiled = profiles.Keys.ToArray(),
            Streamed = streams.Keys.ToArray(),
        };
    }

    /// <summary>
    /// The service-mode rules: a service listens on its own well-known OS endpoint (never supplied streams) of this platform's transport and
    /// serves no child registration; a parent-child server has no stream lane and its method profiles may only lower the data deadlines.
    /// </summary>
    private void ValidateServiceMode(bool service, LocalRpcLimits limits)
    {
        if (service)
        {
            if (_registration is not null)
            {
                throw new InvalidOperationException("A service-mode server serves no child registration.");
            }

            if (_peerResolver is null)
            {
                if (_endpoint is null)
                {
                    throw new InvalidOperationException("A service-mode server listens on its well-known endpoint, not on supplied streams.");
                }

                var native = OperatingSystem.IsWindows() ? LocalRpcTransport.NamedPipe : LocalRpcTransport.UnixDomainSocket;
                if (_endpoint.Transport != native || !(OperatingSystem.IsWindows() || OperatingSystem.IsLinux()))
                {
                    throw new PlatformNotSupportedException("A service-mode endpoint is a Named Pipe on Windows and a Unix domain socket on Linux, where the peer can be read.");
                }
            }

            return;
        }

        if (_streams.Count > 0)
        {
            throw new InvalidOperationException("The stream lane is a service-mode lane; a parent-child server's streams stay data calls.");
        }

        if (_profiles.Values.Any(profile => profile.MaxDeadline > limits.MaxCallDeadline))
        {
            throw new InvalidOperationException("A parent-child server's method profile may only lower the data deadlines.");
        }
    }

    /// <summary>Declares a bootstrap method as the control operation the registration needs; the owner may have declared it already, but never as another operation.</summary>
    private void DeclareRegistrationControl(string path, LocalRpcControlOperation operation)
    {
        var key = path[1..];
        if (_control.TryGetValue(key, out var declared))
        {
            if (declared != operation)
            {
                throw new InvalidOperationException("A registration's bootstrap method is the " + operation + " control operation, not " + declared + ".");
            }

            return;
        }

        _control.Add(key, operation);
    }

    /// <summary>The registration's own decision first (a registered child is admitted no further connection), then the owner's.</summary>
    private static Func<LocalRpcConnectionInfo, CancellationToken, ValueTask<bool>> WithRegistration(
        LocalRpcRegistration registration,
        Func<LocalRpcConnectionInfo, CancellationToken, ValueTask<bool>>? owner) =>
        async (connection, cancellationToken) =>
            await registration.AuthorizeConnectionAsync(connection, cancellationToken).ConfigureAwait(false)
            && (owner is null || await owner(connection, cancellationToken).ConfigureAwait(false));

    /// <summary>
    /// The private profile has no compression: a request that names any encoding other than identity is answered with
    /// a gRPC status before routing, so no message is ever decompressed and the 4 MiB bound holds for the wire and the
    /// decoded size alike.
    /// </summary>
    private static Task RefuseCompressedRequestsAsync(HttpContext context, RequestDelegate next)
    {
        if (context.Request.Headers.TryGetValue("grpc-encoding", out var encoding)
            && encoding.Count > 0
            && !string.Equals(encoding[0], "identity", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = StatusCodes.Status200OK;
            context.Response.ContentType = "application/grpc";
            context.Response.Headers["grpc-status"] = ((int)StatusCode.Unimplemented).ToString(System.Globalization.CultureInfo.InvariantCulture);
            context.Response.Headers["grpc-message"] = "Compression is not supported.";
            return Task.CompletedTask;
        }

        return next(context);
    }

    private void EnsureNotBuilt()
    {
        if (_built)
        {
            throw new InvalidOperationException("A server builder builds one server.");
        }
    }

    /// <summary>Holds the route builder the host creates when it starts, so start-up can read the routes it served.</summary>
    internal sealed class RouteCapture
    {
        internal IEndpointRouteBuilder? Builder { get; set; }
    }

    private sealed record ServiceRegistration(Action<IServiceCollection> Register, Action<IEndpointRouteBuilder> Map);

    private sealed class InertHostLifetime : IHostLifetime
    {
        public Task WaitForStartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}

/// <summary>
/// A parent-owned helper/extension gRPC server over exactly one private OS stream transport. It never binds a TCP
/// listener, never reads a URL or Kestrel endpoint configuration and never discovers peers.
/// </summary>
public sealed class LocalRpcServer : IAsyncDisposable
{
    private readonly IHost _host;
    private readonly LocalRpcLimits _limits;
    private readonly LocalRpcStreamSupplier? _supplier;
    private readonly LocalRpcBoundsRegistry _bounds;
    private readonly IReadOnlyDictionary<string, LocalRpcControlOperation> _control;
    private readonly LocalRpcServerBuilder.RouteCapture _routes;
    private readonly Func<IEnumerable<string>?, IEnumerable<string>?>? _addressView;
    private readonly LocalRpcChildDeclaration? _declaration;
    private int _state;

    internal LocalRpcServer(
        IHost host,
        LocalRpcLimits limits,
        LocalRpcStreamSupplier? supplier,
        LocalRpcBoundsRegistry bounds,
        IReadOnlyDictionary<string, LocalRpcControlOperation> control,
        LocalRpcServerBuilder.RouteCapture routes,
        Func<IEnumerable<string>?, IEnumerable<string>?>? addressView,
        LocalRpcChildDeclaration? declaration)
    {
        _declaration = declaration;
        _addressView = addressView;
        _host = host;
        _limits = limits;
        _supplier = supplier;
        _bounds = bounds;
        _control = control;
        _routes = routes;
    }

    internal IServiceProvider Services => _host.Services;

    /// <summary>The methods with a deadline profile (service/method).</summary>
    internal IReadOnlyList<string> Profiled { get; init; } = [];

    /// <summary>The stream-lane methods (service/method).</summary>
    internal IReadOnlyList<string> Streamed { get; init; } = [];

    /// <summary>Begins registering a server that listens on one endpoint of one transport.</summary>
    public static LocalRpcServerBuilder CreateBuilder(LocalRpcEndpoint endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        return new LocalRpcServerBuilder(endpoint, null);
    }

    /// <summary>Begins registering a server that accepts only the already-connected streams a launcher supplies.</summary>
    public static LocalRpcServerBuilder CreateBuilder(LocalRpcStreamSupplier streams)
    {
        ArgumentNullException.ThrowIfNull(streams);
        return new LocalRpcServerBuilder(null, streams);
    }

    /// <summary>The call bounds of every connected peer right now, with the admitted and refused totals since start.</summary>
    public LocalRpcBoundsSnapshot GetBoundsSnapshot() => _bounds.Snapshot();

    /// <summary>The stream lane and the peer decisions of a service-mode server right now, with totals since start (all zero for a parent-child server).</summary>
    public LocalRpcServiceSnapshot GetServiceSnapshot() => _bounds.ServiceSnapshot();

    /// <summary>
    /// Starts listening. The server refuses to run if any IP-based address is bound, if any other connection listener
    /// is registered, if a declared control method is not served by a registered service, or if the services served are not
    /// exactly the declared ones (<see cref="LocalRpcServerBuilder.RequireDeclaredServices"/>).
    /// </summary>
    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        if (Interlocked.CompareExchange(ref _state, 1, 0) != 0)
        {
            throw new InvalidOperationException("A server starts once.");
        }

        var factories = _host.Services.GetServices<IConnectionListenerFactory>().ToArray();
        if (factories.Length != 1 || factories[0] is not LocalRpcConnectionListenerFactory)
        {
            throw new InvalidOperationException("Only the private stream transport may listen.");
        }

        await _host.StartAsync(cancellationToken).ConfigureAwait(false);
        var addresses = _host.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>();
        IEnumerable<string>? reported = addresses?.Addresses;
        var failure = PrivateTransportViolation(_addressView is null ? reported : _addressView(reported)) ?? UnservedControlMethod() ?? UnservedLaneMethod() ?? UndeclaredServices();
        if (failure is not null)
        {
            await _host.StopAsync(CancellationToken.None).ConfigureAwait(false);
            throw new InvalidOperationException(failure);
        }
    }

    /// <summary>Why the bound addresses are not exclusively the private transport, or null when they are.</summary>
    internal static string? PrivateTransportViolation(IEnumerable<string>? addresses)
    {
        // Kestrel lists a custom endpoint as http://<EndPoint.ToString()>; any other entry is an IP/URL binding.
        var bound = addresses?.ToArray();
        return bound is null || bound.Any(address => !address.StartsWith("http://localrpc:", StringComparison.Ordinal))
            ? "An IP address was bound (" + string.Join(", ", bound ?? []) + "); a private helper server never listens on TCP."
            : null;
    }

    private HashSet<string> ServedMethods() => ServedMethodTypes().Keys.ToHashSet(StringComparer.Ordinal);

    private Dictionary<string, MethodType> ServedMethodTypes()
    {
        var served = new Dictionary<string, MethodType>(StringComparer.Ordinal);
        foreach (var source in _routes.Builder?.DataSources ?? [])
        {
            foreach (var endpoint in source.Endpoints)
            {
                if (endpoint.Metadata.GetMetadata<GrpcMethodMetadata>() is { } method)
                {
                    served[method.Method.ServiceName + "/" + method.Method.Name] = method.Method.Type;
                }
            }
        }

        return served;
    }

    /// <summary>Why a profiled or stream-lane method would not run as registered (not served, or a stream method that is not server-streaming), or null.</summary>
    private string? UnservedLaneMethod()
    {
        var served = ServedMethodTypes();
        var missing = Profiled.Concat(Streamed).Where(key => !served.ContainsKey(key)).Order(StringComparer.Ordinal).ToArray();
        if (missing.Length > 0)
        {
            return "A profiled or stream-lane method is not served by any registered service (" + string.Join(", ", missing) + ").";
        }

        var notStreaming = Streamed.Where(key => served[key] != MethodType.ServerStreaming).Order(StringComparer.Ordinal).ToArray();
        return notStreaming.Length == 0
            ? null
            : "A stream-lane method is not a server-streaming method (" + string.Join(", ", notStreaming) + ").";
    }

    private string? UnservedControlMethod()
    {
        var served = ServedMethods();
        var missing = _control.Keys.Where(key => !served.Contains(key)).Order(StringComparer.Ordinal).ToArray();
        return missing.Length == 0
            ? null
            : "A control method is not served by any registered service (" + string.Join(", ", missing) + "); it would run as a data call.";
    }

    /// <summary>Why the served services are not exactly the declared ones, or null when they are (or nothing was declared).</summary>
    private string? UndeclaredServices()
    {
        if (_declaration is null)
        {
            return null;
        }

        var served = ServedMethods().Select(method => method[..method.IndexOf('/', StringComparison.Ordinal)]).ToHashSet(StringComparer.Ordinal);
        var declared = _declaration.Services.Select(service => service.ServiceName).ToHashSet(StringComparer.Ordinal);
        var extra = served.Where(name => !declared.Contains(name)).Order(StringComparer.Ordinal).ToArray();
        var missing = declared.Where(name => !served.Contains(name)).Order(StringComparer.Ordinal).ToArray();
        if (extra.Length == 0 && missing.Length == 0)
        {
            return null;
        }

        return (extra.Length == 0 ? string.Empty : "A service is served that the child did not declare (" + string.Join(", ", extra) + "). ")
            + (missing.Length == 0 ? string.Empty : "A declared service is not served (" + string.Join(", ", missing) + ").");
    }

    /// <summary>Stops accepting, completes in-flight calls within the shutdown bound and closes every connection.</summary>
    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        if (Volatile.Read(ref _state) == 1)
        {
            await _host.StopAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Stops the server, releases the endpoint and disposes streams that were never accepted.</summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _state, 2) == 2)
        {
            return;
        }

        using var timeout = new CancellationTokenSource(_limits.ShutdownTimeout + TimeSpan.FromSeconds(1));
        try
        {
            await _host.StopAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Bounded shutdown: remaining connections are closed by disposing the host.
        }
        finally
        {
            _host.Dispose();
            if (_supplier is not null)
            {
                await _supplier.DisposeUnacceptedAsync().ConfigureAwait(false);
            }
        }
    }
}
