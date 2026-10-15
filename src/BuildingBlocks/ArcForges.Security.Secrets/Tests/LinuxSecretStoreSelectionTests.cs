// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace ArcForges.Security.Secrets.Tests;

/// <summary>
/// The Linux Secret Service backend against a real private GNOME Keyring, and the selection between it and the owner-only file
/// fallback with the protection each reports. Nothing here reaches the user's session bus or keyring: every test names its own bus.
/// The private-keyring tests are an explicit local opt-in (<c>ARCFORGES_LOCAL_OS_SECRET_STORE=1</c>) and are skipped, with the
/// reason, when <c>gnome-keyring-daemon</c>, <c>dbus-daemon</c>, <c>secret-tool</c> or <c>dbus-send</c> is not installed.
/// </summary>
public sealed class LinuxSecretStoreSelectionTests : IDisposable
{
    private const string LinuxOnly = "The Secret Service and the file fallback are the Linux backends.";
    private const string LocalSecretServiceOptIn =
        "Explicit local Linux opt-in (ARCFORGES_LOCAL_OS_SECRET_STORE=1): starts a private dbus-daemon and gnome-keyring-daemon.";

    private readonly string _root = Directory.CreateTempSubdirectory("afsel-").FullName;

    public static bool OnLinux => OperatingSystem.IsLinux();

    public static bool LocalSecretServiceEnabled => OperatingSystem.IsLinux()
        && Environment.GetEnvironmentVariable("ARCFORGES_LOCAL_OS_SECRET_STORE") == "1";

    private string DataRoot => Path.Combine(_root, "data");

    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact(Skip = LinuxOnly, SkipUnless = nameof(OnLinux))]
    [SupportedOSPlatform("linux")]
    public void WithoutASessionBusTheFallbackIsSelectedAndReportedAsFileOwnerOnly()
    {
        var selection = OsSecretStore.SelectLinux(DataRoot, new SecretServiceOptions(), sessionBusAddress: null);

        Assert.Equal(SecretStoreBackend.OwnerOnlyFile, selection.Backend);
        Assert.Equal(SecretStoreProtection.FileOwnerOnly, selection.Protection);
        Assert.False(selection.CredentialInOsStore);
        Assert.Contains("No session D-Bus", selection.FallbackReason, StringComparison.Ordinal);
        var store = Assert.IsType<OwnerOnlyFileSecretStore>(selection.Store);
        Assert.Equal(Path.Combine(DataRoot, "run", "secrets"), store.SecretDirectory);
        selection.Store.Write("node-credential", "fallback"u8);
        Assert.Equal("fallback"u8.ToArray(), selection.Store.Read("node-credential"));
    }

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

    [Fact(Skip = LocalSecretServiceOptIn, SkipUnless = nameof(LocalSecretServiceEnabled))]
    [SupportedOSPlatform("linux")]
    public void ThePrivateKeyringIsSelectedReportedAsOsStoreAndRoundTripsThroughTheDefaultCollection()
    {
        PrivateSecretServiceKeyring.RequireTools("dbus-daemon", "gnome-keyring-daemon", "secret-tool", "dbus-send");
        using var keyring = PrivateSecretServiceKeyring.Start(withKeyring: true);
        var selection = OsSecretStore.SelectForCurrentPlatform(DataRoot, keyring.Options);

        Assert.Equal(SecretStoreBackend.SecretService, selection.Backend);
        Assert.Equal(SecretStoreProtection.OsSecretStore, selection.Protection);
        Assert.True(selection.CredentialInOsStore);
        Assert.Null(selection.FallbackReason);
        var store = Assert.IsType<SecretServiceSecretStore>(selection.Store);
        Assert.Equal(SecretStoreIsolation.SameUserShared, store.Isolation);
        Assert.Equal(SecretStoreProtection.OsSecretStore, SecretServiceSecretStore.Protection);
        Assert.True(store.NegotiatesEncryptedTransport()); // gnome-keyring accepts dh-ietf1024-sha256-aes128-cbc-pkcs7
        Assert.False(Directory.Exists(Path.Combine(DataRoot, "run"))); // no file fallback was touched

        string key = "node-credential-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(4));
        byte[] first = Encoding.ASCII.GetBytes(Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32)));
        byte[] second = Encoding.ASCII.GetBytes(Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(40)));
        Assert.Null(store.Read(key));
        Assert.False(store.Delete(key));

        store.Write(key, first);
        Assert.Equal(first, store.Read(key));
        // libsecret's secret-tool, an independent client, finds the item by the design's attributes in the default collection.
        AssertLibsecretLookup(keyring, key, first);
        store.Write(key, second); // replaces the item with the same attributes
        Assert.Equal(second, store.Read(key));
        AssertLibsecretLookup(keyring, key, second);
        // Exactly one item carries the key, and it is in the default collection (the private keyring's "login").
        var search = keyring.SecretTool(null, "search", "--all", "application", "arcforges", "name", key);
        Assert.Equal(0, search.ExitCode);
        Assert.Equal(1, Encoding.UTF8.GetString(search.Output).Split('\n').Count(line => line.StartsWith('[')));
        Assert.Contains("/org/freedesktop/secrets/collection/login", keyring.DBusSend("--dest=org.freedesktop.secrets",
            "/org/freedesktop/secrets", "org.freedesktop.Secret.Service.ReadAlias", "string:default").Output.AsUtf8(), StringComparison.Ordinal);
        var inDefault = keyring.DBusSend("--dest=org.freedesktop.secrets", "/org/freedesktop/secrets/collection/login",
            "org.freedesktop.Secret.Collection.SearchItems", "dict:string:string:application,arcforges,name," + key);
        Assert.Equal(1, CountOccurrences(inDefault.Output.AsUtf8(), "/org/freedesktop/secrets/collection/login/"));

        Assert.True(store.Delete(key));
        Assert.Null(store.Read(key));
        Assert.NotEqual(0, keyring.SecretTool(null, "lookup", "application", "arcforges", "name", key).ExitCode);
        Assert.False(store.Delete(key));
        Assert.False(Directory.Exists(Path.Combine(DataRoot, "run")));
    }

    [Fact(Skip = LocalSecretServiceOptIn, SkipUnless = nameof(LocalSecretServiceEnabled))]
    [SupportedOSPlatform("linux")]
    public void AnItemStoredByLibsecretIsReadAndDeletedByTheStore()
    {
        PrivateSecretServiceKeyring.RequireTools("dbus-daemon", "gnome-keyring-daemon", "secret-tool");
        using var keyring = PrivateSecretServiceKeyring.Start(withKeyring: true);
        Assert.True(SecretServiceSecretStore.TryOpen(keyring.Options, out var store, out string? reason), reason);
        string key = "node-data-key-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(4));
        byte[] value = Encoding.ASCII.GetBytes(Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32)));

        Assert.Equal(0, keyring.SecretTool(value, "store", "--label=af-dp-02 test", "application", "arcforges", "name", key).ExitCode);

        Assert.Equal(value, store.Read(key));
        Assert.True(store.Delete(key));
        Assert.NotEqual(0, keyring.SecretTool(null, "lookup", "application", "arcforges", "name", key).ExitCode);
    }

    [Fact(Skip = LocalSecretServiceOptIn, SkipUnless = nameof(LocalSecretServiceEnabled))]
    [SupportedOSPlatform("linux")]
    public void ABusWithoutASecretServiceSelectsTheFallbackAndTheStrictEntryPointRefuses()
    {
        using var bus = PrivateSecretServiceKeyring.Start(withKeyring: false);

        var selection = OsSecretStore.SelectForCurrentPlatform(DataRoot, bus.Options);

        Assert.Equal(SecretStoreBackend.OwnerOnlyFile, selection.Backend);
        Assert.Equal(SecretStoreProtection.FileOwnerOnly, selection.Protection);
        Assert.False(selection.CredentialInOsStore);
        Assert.Contains("org.freedesktop.DBus.Error.ServiceUnknown", selection.FallbackReason, StringComparison.Ordinal);
        TestContext.Current.TestOutputHelper?.WriteLine("Bus without a Secret Service: " + selection.FallbackReason);
        Assert.Throws<PlatformNotSupportedException>(() => OsSecretStore.Create(isWindows: false, bus.Options));
    }

    [Fact(Skip = LocalSecretServiceOptIn, SkipUnless = nameof(LocalSecretServiceEnabled))]
    [SupportedOSPlatform("linux")]
    public void AKeyringWithoutADefaultCollectionIsUnavailableSoTheFallbackIsSelectedAndNoCollectionIsCreated()
    {
        PrivateSecretServiceKeyring.RequireTools("dbus-daemon", "gnome-keyring-daemon", "dbus-send");
        // gnome-keyring started without --unlock in a fresh home: the headless state of a WSL session without a login keyring.
        using var keyring = PrivateSecretServiceKeyring.Start(withKeyring: true, unlock: false);
        string ReadDefaultAlias() => keyring.DBusSend("--dest=org.freedesktop.secrets", "/org/freedesktop/secrets",
            "org.freedesktop.Secret.Service.ReadAlias", "string:default").Output.AsUtf8();
        Assert.Contains("object path \"/\"", ReadDefaultAlias(), StringComparison.Ordinal);

        var selection = OsSecretStore.SelectForCurrentPlatform(DataRoot, keyring.Options);

        Assert.Equal(SecretStoreBackend.OwnerOnlyFile, selection.Backend);
        Assert.Equal(SecretStoreProtection.FileOwnerOnly, selection.Protection);
        Assert.False(selection.CredentialInOsStore);
        Assert.Contains("no default collection", selection.FallbackReason, StringComparison.Ordinal);
        TestContext.Current.TestOutputHelper?.WriteLine("Keyring without a default collection: " + selection.FallbackReason);
        Assert.False(SecretServiceSecretStore.TryOpen(keyring.Options, out _, out _));
        Assert.Throws<PlatformNotSupportedException>(() => OsSecretStore.Create(isWindows: false, keyring.Options));
        selection.Store.Write("node-credential", "fallback"u8);
        Assert.Equal("fallback"u8.ToArray(), selection.Store.Read("node-credential"));
        Assert.Contains("object path \"/\"", ReadDefaultAlias(), StringComparison.Ordinal); // no collection was created
    }

    [Fact(Skip = LocalSecretServiceOptIn, SkipUnless = nameof(LocalSecretServiceEnabled))]
    [SupportedOSPlatform("linux")]
    public void ALockedDefaultCollectionPromptsAndAnUnansweredPromptFailsWithoutAnyFallback()
    {
        PrivateSecretServiceKeyring.RequireTools("dbus-daemon", "gnome-keyring-daemon", "dbus-send");
        using var keyring = PrivateSecretServiceKeyring.Start(withKeyring: true);
        var store = Assert.IsType<SecretServiceSecretStore>(OsSecretStore.Create(isWindows: false, keyring.Options));
        store.Write("node-credential", "before-lock"u8);
        var locked = keyring.DBusSend("--dest=org.freedesktop.secrets", "/org/freedesktop/secrets",
            "org.freedesktop.Secret.Service.Lock", "array:objpath:/org/freedesktop/secrets/collection/login");
        Assert.Equal(0, locked.ExitCode);

        // The store asks the service to unlock and runs the returned prompt. This private bus has no desktop prompter, so the prompt
        // is dismissed (or never answered): the operation fails closed and nothing is written anywhere else.
        var failure = Record.Exception(() => store.Write("node-credential", "after-lock"u8));
        Assert.True(failure is UnauthorizedAccessException or TimeoutException, failure?.ToString());
        Assert.NotNull(failure);
        TestContext.Current.TestOutputHelper?.WriteLine("Locked collection: " + failure.GetType().Name + ": " + failure.Message);
        Assert.Contains("prompt", failure.Message, StringComparison.Ordinal);
        Assert.Throws(failure.GetType(), () => store.Read("node-credential"));
        Assert.False(Directory.Exists(Path.Combine(DataRoot, "run")));
    }

    [SupportedOSPlatform("linux")]
    private static void AssertLibsecretLookup(PrivateSecretServiceKeyring keyring, string key, byte[] expected)
    {
        var (exitCode, output) = keyring.SecretTool(null, "lookup", "application", "arcforges", "name", key);
        Assert.Equal(0, exitCode);
        Assert.Equal(expected, output);
    }

    private static int CountOccurrences(string text, string value)
    {
        int count = 0;
        for (int index = text.IndexOf(value, StringComparison.Ordinal); index >= 0;
            index = text.IndexOf(value, index + value.Length, StringComparison.Ordinal))
        {
            count++;
        }

        return count;
    }
}

internal static class ByteText
{
    public static string AsUtf8(this byte[] bytes) => Encoding.UTF8.GetString(bytes);
}
