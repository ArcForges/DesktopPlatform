// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Security.Secrets;
using Xunit;

namespace ArcForges.Tests.OsSecretStoreTests;

/// <summary>
/// The Linux Secret Service backend and its selection against a real, private GNOME Keyring (the OS secret-store tier; formerly the
/// local opt-in ARCFORGES_LOCAL_OS_SECRET_STORE tests of ArcForges.Security.Secrets.Tests). They run only in the isolated
/// Linux secret-store test host (its marker file, ArcForges-Design AD-0019 section 6) with ARCFORGES_OS_SECRET_STORE_TESTS=1, never in the verification account or a WSL distribution, and are skipped
/// with the reason when the Secret Service provider (gnome-keyring) or its tools are not installed there. Every test starts its own
/// dbus-daemon and gnome-keyring-daemon in a new temporary directory, so even there the user's session bus and keyring are never
/// contacted; each store call is counted by the tier fixture, and entry names come from its name list.
/// </summary>
[Collection(OsSecretStoreTierDefinition.Name)]
[Trait("env", "os-secret-store")]
[SupportedOSPlatform("linux")]
public sealed class SecretServiceTierTests(OsSecretStoreTier tier) : IDisposable
{
    private const string PrivateKeyringGone = "the private keyring and its files were deleted with the test";
    private readonly string _root = Directory.CreateTempSubdirectory("afsst-").FullName;

    private string DataRoot => Path.Combine(_root, "data");

    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact(Skip = OsSecretStoreTier.LinuxTierReason, SkipUnless = nameof(OsSecretStoreTier.LinuxTier), SkipType = typeof(OsSecretStoreTier))]
    public void WithoutASessionBusTheFallbackIsSelectedAndReportedAsFileOwnerOnly()
    {
        // No bus exists at all, so no store is called; this needs the opt-in only because the tripwire refuses an implicit bus.
        var selection = OsSecretStore.SelectLinux(DataRoot, new SecretServiceOptions(), sessionBusAddress: null);

        Assert.Equal(SecretStoreBackend.OwnerOnlyFile, selection.Backend);
        Assert.Equal(SecretStoreProtection.FileOwnerOnly, selection.Protection);
        Assert.False(selection.CredentialInOsStore);
        Assert.Contains("No session D-Bus", selection.FallbackReason, StringComparison.Ordinal);
        selection.Store.Write("node-credential", "fallback"u8);
        Assert.Equal("fallback"u8.ToArray(), selection.Store.Read("node-credential"));
    }

    [Fact(Skip = OsSecretStoreTier.LinuxTierReason, SkipUnless = nameof(OsSecretStoreTier.LinuxTier), SkipType = typeof(OsSecretStoreTier))]
    public void ThePrivateKeyringIsSelectedReportedAsOsStoreAndRoundTripsThroughTheDefaultCollection()
    {
        PrivateSecretServiceKeyring.RequireTools("dbus-daemon", "gnome-keyring-daemon", "secret-tool", "dbus-send");
        using var keyring = PrivateSecretServiceKeyring.Start(tier, withKeyring: true);
        var selection = tier.Call("select", () => OsSecretStore.SelectForCurrentPlatform(DataRoot, keyring.Options));

        Assert.Equal(SecretStoreBackend.SecretService, selection.Backend);
        Assert.Equal(SecretStoreProtection.OsSecretStore, selection.Protection);
        Assert.True(selection.CredentialInOsStore);
        Assert.Null(selection.FallbackReason);
        var store = Assert.IsType<SecretServiceSecretStore>(selection.Store);
        Assert.Equal(SecretStoreIsolation.SameUserShared, store.Isolation);
        Assert.True(tier.Call("negotiate", store.NegotiatesEncryptedTransport)); // dh-ietf1024-sha256-aes128-cbc-pkcs7

        string name = tier.NewEntry(store);
        byte[] first = Encoding.ASCII.GetBytes(Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32)));
        byte[] second = Encoding.ASCII.GetBytes(Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(40)));
        try
        {
            tier.Call("write", () => store.Write(name, first));
            Assert.Equal(first, tier.Call("read", () => store.Read(name)));
            // libsecret's secret-tool, an independent client, finds the item by the design's attributes in the default collection.
            var lookup = tier.Call("secret-tool lookup", () => keyring.SecretTool(null, "lookup", "application", "arcforges", "name", name));
            Assert.Equal(0, lookup.ExitCode);
            Assert.Equal(first, lookup.Output);
            tier.Call("overwrite", () => store.Write(name, second)); // replaces the item with the same attributes
            Assert.Equal(second, tier.Call("read", () => store.Read(name)));
        }
        finally
        {
            tier.Remove(name);
        }

        Assert.False(Directory.Exists(Path.Combine(DataRoot, "run"))); // no file fallback was touched
    }

    [Fact(Skip = OsSecretStoreTier.LinuxTierReason, SkipUnless = nameof(OsSecretStoreTier.LinuxTier), SkipType = typeof(OsSecretStoreTier))]
    public void AnItemStoredByLibsecretIsReadAndDeletedByTheStore()
    {
        PrivateSecretServiceKeyring.RequireTools("dbus-daemon", "gnome-keyring-daemon", "secret-tool", "dbus-send");
        using var keyring = PrivateSecretServiceKeyring.Start(tier, withKeyring: true);
        SecretServiceSecretStore? opened = null;
        string? reason = null;
        Assert.True(tier.Call("open", () => SecretServiceSecretStore.TryOpen(keyring.Options, out opened, out reason)), reason);
        var store = opened!;
        string name = tier.NewEntry(store);
        byte[] value = Encoding.ASCII.GetBytes(Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32)));
        try
        {
            var stored = tier.Call("secret-tool store", () => keyring.SecretTool(value, "store", "--label=os-secret-store tier",
                "application", "arcforges", "name", name));
            Assert.Equal(0, stored.ExitCode);
            Assert.Equal(value, tier.Call("read", () => store.Read(name)));
        }
        finally
        {
            tier.Remove(name);
        }
    }

    [Fact(Skip = OsSecretStoreTier.LinuxTierReason, SkipUnless = nameof(OsSecretStoreTier.LinuxTier), SkipType = typeof(OsSecretStoreTier))]
    public void ABusWithoutASecretServiceSelectsTheFallbackAndTheStrictEntryPointRefuses()
    {
        PrivateSecretServiceKeyring.RequireTools("dbus-daemon");
        using var bus = PrivateSecretServiceKeyring.Start(tier, withKeyring: false);

        var selection = tier.Call("select", () => OsSecretStore.SelectForCurrentPlatform(DataRoot, bus.Options));

        Assert.Equal(SecretStoreBackend.OwnerOnlyFile, selection.Backend);
        Assert.Equal(SecretStoreProtection.FileOwnerOnly, selection.Protection);
        Assert.False(selection.CredentialInOsStore);
        Assert.Contains("org.freedesktop.DBus.Error.ServiceUnknown", selection.FallbackReason, StringComparison.Ordinal);
        TestContext.Current.TestOutputHelper?.WriteLine("Bus without a Secret Service: " + selection.FallbackReason);
        Assert.Throws<PlatformNotSupportedException>(() => tier.Call("create", () => OsSecretStore.Create(isWindows: false, bus.Options)));
    }

    [Fact(Skip = OsSecretStoreTier.LinuxTierReason, SkipUnless = nameof(OsSecretStoreTier.LinuxTier), SkipType = typeof(OsSecretStoreTier))]
    public void AKeyringWithoutADefaultCollectionIsUnavailableSoTheFallbackIsSelectedAndNoCollectionIsCreated()
    {
        PrivateSecretServiceKeyring.RequireTools("dbus-daemon", "gnome-keyring-daemon", "dbus-send");
        // gnome-keyring started without --unlock in a fresh home: the headless state of a session without a login keyring.
        using var keyring = PrivateSecretServiceKeyring.Start(tier, withKeyring: true, unlock: false);

        var selection = tier.Call("select", () => OsSecretStore.SelectForCurrentPlatform(DataRoot, keyring.Options));

        Assert.Equal(SecretStoreBackend.OwnerOnlyFile, selection.Backend);
        Assert.Equal(SecretStoreProtection.FileOwnerOnly, selection.Protection);
        Assert.False(selection.CredentialInOsStore);
        Assert.Contains("no default collection", selection.FallbackReason, StringComparison.Ordinal);
        TestContext.Current.TestOutputHelper?.WriteLine("Keyring without a default collection: " + selection.FallbackReason);
        Assert.Throws<PlatformNotSupportedException>(() => tier.Call("create", () => OsSecretStore.Create(isWindows: false, keyring.Options)));
        selection.Store.Write("node-credential", "fallback"u8);
        Assert.Equal("fallback"u8.ToArray(), selection.Store.Read("node-credential"));
        var alias = tier.Call("read alias", () => keyring.DBusSend("--dest=org.freedesktop.secrets", "/org/freedesktop/secrets",
            "org.freedesktop.Secret.Service.ReadAlias", "string:default"));
        Assert.Contains("object path \"/\"", alias.Output.AsUtf8(), StringComparison.Ordinal); // no collection was created
    }

    [Fact(Skip = OsSecretStoreTier.LinuxTierReason, SkipUnless = nameof(OsSecretStoreTier.LinuxTier), SkipType = typeof(OsSecretStoreTier))]
    public void ALockedDefaultCollectionPromptsAndAnUnansweredPromptFailsWithoutAnyFallback()
    {
        PrivateSecretServiceKeyring.RequireTools("dbus-daemon", "gnome-keyring-daemon", "dbus-send");
        using var keyring = PrivateSecretServiceKeyring.Start(tier, withKeyring: true);
        // A short prompt bound keeps each refused call well inside the tier's per-call timeout.
        var options = new SecretServiceOptions
        {
            BusAddress = keyring.Address,
            CallTimeout = TimeSpan.FromSeconds(5),
            PromptTimeout = TimeSpan.FromSeconds(3),
        };
        var store = Assert.IsType<SecretServiceSecretStore>(tier.Call("create", () => OsSecretStore.Create(isWindows: false, options)));
        var locked = tier.Call("lock", () => keyring.DBusSend("--dest=org.freedesktop.secrets", "/org/freedesktop/secrets",
            "org.freedesktop.Secret.Service.Lock", "array:objpath:/org/freedesktop/secrets/collection/login"));
        Assert.Equal(0, locked.ExitCode);

        // The store asks the service to unlock and runs the returned prompt. This private bus has no desktop prompter, so the prompt
        // is dismissed (or never answered): the operation fails closed and nothing is written anywhere else.
        string name = tier.NewEntry(store);
        var failure = Record.Exception(() => tier.Call("write while locked", () => store.Write(name, "after-lock"u8.ToArray())));
        Assert.True(failure is UnauthorizedAccessException or TimeoutException, failure?.ToString());
        Assert.NotNull(failure);
        TestContext.Current.TestOutputHelper?.WriteLine("Locked collection: " + failure.GetType().Name + ": " + failure.Message);
        Assert.Contains("prompt", failure.Message, StringComparison.Ordinal);
        // The entry was never created, and the private keyring is destroyed with this test.
        tier.Discard(name, "its write failed closed on the locked collection; " + PrivateKeyringGone);
        Assert.False(Directory.Exists(Path.Combine(DataRoot, "run")));
    }
}

internal static class ByteText
{
    public static string AsUtf8(this byte[] bytes) => Encoding.UTF8.GetString(bytes);
}
