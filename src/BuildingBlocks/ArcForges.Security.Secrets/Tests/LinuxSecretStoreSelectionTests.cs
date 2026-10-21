// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using Xunit;

namespace ArcForges.Security.Secrets.Tests;

/// <summary>
/// The Linux selection between the Secret Service and the owner-only file fallback with the protection each reports, over buses
/// that this test owns. Nothing here reaches the user's session bus or keyring: every selection names a bus address that does not
/// exist, and the test tripwire (<see cref="OsSecretStoreGuard"/>) refuses anything else (OsSecretStoreGuardTests). The tests
/// against a real Secret Service (a private dbus-daemon and gnome-keyring-daemon) and the selection without any session bus belong
/// to the OS secret-store integration tier (tests/OsSecretStoreTests), which runs only with ARCFORGES_OS_SECRET_STORE_TESTS=1 in the
/// isolated Linux secret-store test host (ArcForges-Design AD-0019 section 6).
/// </summary>
public sealed class LinuxSecretStoreSelectionTests : IDisposable
{
    private const string LinuxOnly = "The Secret Service and the file fallback are the Linux backends.";

    private readonly string _root = Directory.CreateTempSubdirectory("afsel-").FullName;

    public static bool OnLinux => OperatingSystem.IsLinux();

    private string DataRoot => Path.Combine(_root, "data");

    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact(Skip = LinuxOnly, SkipUnless = nameof(OnLinux))]
    [SupportedOSPlatform("linux")]
    public void AnUnreachableSessionBusMakesTheSecretServiceUnavailable()
    {
        var options = new SecretServiceOptions
        {
            BusAddress = "unix:path=" + Path.Combine(_root, "no-bus-here"),
            CallTimeout = TimeSpan.FromSeconds(5),
        };

        var selection = OsSecretStore.SelectForCurrentPlatform(DataRoot, options);

        Assert.Equal(SecretStoreBackend.OwnerOnlyFile, selection.Backend);
        Assert.Equal(SecretStoreProtection.FileOwnerOnly, selection.Protection);
        Assert.False(selection.CredentialInOsStore);
        Assert.Contains("not available on the session bus", selection.FallbackReason, StringComparison.Ordinal);
        Assert.False(SecretServiceSecretStore.TryOpen(options, out _, out _));
        // The strict OS-store entry point never falls back to a file.
        Assert.Throws<PlatformNotSupportedException>(() => OsSecretStore.Create(isWindows: false, options));
    }

    [Fact(Skip = LinuxOnly, SkipUnless = nameof(OnLinux))]
    [SupportedOSPlatform("linux")]
    public void TheSessionBusIsTheEnvironmentAddressOrTheUserBusSocketAndOtherwiseAbsent()
    {
        string runtime = Path.Combine(_root, "runtime");
        Directory.CreateDirectory(runtime);

        Assert.Equal("unix:path=/run/user/4242/bus", SecretServiceSecretStore.ResolveSessionBusAddress("unix:path=/run/user/4242/bus", runtime));
        Assert.Null(SecretServiceSecretStore.ResolveSessionBusAddress(null, runtime)); // no bus socket in the runtime directory
        Assert.Null(SecretServiceSecretStore.ResolveSessionBusAddress(" ", null));
        Assert.Null(SecretServiceSecretStore.ResolveSessionBusAddress(null, "relative/runtime"));

        string socketPath = Path.Combine(runtime, "bus");
        using var listener = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.Unix, System.Net.Sockets.SocketType.Stream,
            System.Net.Sockets.ProtocolType.Unspecified);
        listener.Bind(new System.Net.Sockets.UnixDomainSocketEndPoint(socketPath));
        Assert.Equal("unix:path=" + socketPath, SecretServiceSecretStore.ResolveSessionBusAddress(string.Empty, runtime));
    }

    [Fact]
    public void SecretServiceOptionsAreBounded()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new SecretServiceOptions { CallTimeout = TimeSpan.Zero }.Validate());
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new SecretServiceOptions { CallTimeout = SecretServiceOptions.MaximumCallTimeout + TimeSpan.FromTicks(1) }.Validate());
        Assert.Throws<ArgumentOutOfRangeException>(() => new SecretServiceOptions { PromptTimeout = TimeSpan.FromSeconds(-1) }.Validate());
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new SecretServiceOptions { PromptTimeout = SecretServiceOptions.MaximumPromptTimeout + TimeSpan.FromTicks(1) }.Validate());
        Assert.Throws<ArgumentException>(() => new SecretServiceOptions { BusAddress = string.Empty }.Validate());
        new SecretServiceOptions().Validate();
        // The data root is validated before any backend is considered.
        Assert.Throws<ArgumentException>(() => OsSecretStore.SelectForCurrentPlatform(" "));
    }

    [Fact]
    public void BothEndsOfTheTransportKeyExchangeDeriveTheSameAesKey()
    {
        using var client = new SecretServiceKeyExchange();
        using var service = new SecretServiceKeyExchange();
        byte[] clientKey = client.DeriveKey(service.PublicKey);
        byte[] serviceKey = service.DeriveKey(client.PublicKey);

        Assert.Equal(SecretServiceKeyExchange.KeyBytes, clientKey.Length);
        Assert.Equal(clientKey, serviceKey);
        Assert.NotEqual(client.PublicKey, service.PublicKey);
        Assert.Throws<InvalidDataException>(() => client.DeriveKey([1]));
        Assert.Throws<InvalidDataException>(() => client.DeriveKey([]));
        Assert.Throws<InvalidDataException>(() => client.DeriveKey(new byte[129]));
        Assert.Throws<InvalidDataException>(() => client.DeriveKey(Enumerable.Repeat((byte)0xFF, 128).ToArray()));
    }
}
