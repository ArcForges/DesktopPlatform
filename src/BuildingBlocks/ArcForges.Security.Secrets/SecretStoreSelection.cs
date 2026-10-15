// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;

namespace ArcForges.Security.Secrets;

/// <summary>
/// How a selected store protects a value at rest. The node shows anything other than
/// <see cref="OsSecretStore"/> as weaker credential storage (<c>AccountStatus.credential_in_os_store</c>, R-AUTH-003).
/// </summary>
public enum SecretStoreProtection
{
    /// <summary>The operating system's secret store holds the value (Windows Credential Manager, the freedesktop Secret Service).</summary>
    OsSecretStore = 0,

    /// <summary>
    /// A file that only the owning OS user can read (mode 0600 in a 0700 directory). The value is not encrypted by a
    /// secret store; anyone who can act as that user, or read the disk outside the OS, can read it.
    /// </summary>
    FileOwnerOnly = 1,
}

/// <summary>The backend a selection chose.</summary>
public enum SecretStoreBackend
{
    /// <summary>The current Windows user's Credential Manager.</summary>
    WindowsCredentialManager = 0,

    /// <summary><c>org.freedesktop.secrets</c> on the session D-Bus, default collection.</summary>
    SecretService = 1,

    /// <summary>One 0600 file per secret under <c>&lt;data root&gt;/run/secrets/</c>.</summary>
    OwnerOnlyFile = 2,
}

/// <summary>Where and how the Linux Secret Service backend is reached.</summary>
public sealed class SecretServiceOptions
{
    /// <summary>Upper bound of <see cref="CallTimeout"/>.</summary>
    public static readonly TimeSpan MaximumCallTimeout = TimeSpan.FromMinutes(5);

    /// <summary>Upper bound of <see cref="PromptTimeout"/>.</summary>
    public static readonly TimeSpan MaximumPromptTimeout = TimeSpan.FromMinutes(30);

    /// <summary>
    /// The D-Bus address to use. <see langword="null"/> selects the session bus of the process environment
    /// (<c>DBUS_SESSION_BUS_ADDRESS</c>, or the <c>$XDG_RUNTIME_DIR/bus</c> socket when it exists); without one the backend is
    /// unavailable.
    /// </summary>
    public string? BusAddress { get; init; }

    /// <summary>Bound of the connection and of each Secret Service call.</summary>
    public TimeSpan CallTimeout { get; init; } = TimeSpan.FromSeconds(25);

    /// <summary>How long a desktop keyring prompt (for example unlocking a locked collection) may stay unanswered; it is then dismissed.</summary>
    public TimeSpan PromptTimeout { get; init; } = TimeSpan.FromMinutes(2);

    internal void Validate()
    {
        if (CallTimeout <= TimeSpan.Zero || CallTimeout > MaximumCallTimeout)
        {
            throw new ArgumentOutOfRangeException(nameof(CallTimeout), "The Secret Service call timeout must be positive and at most five minutes.");
        }

        if (PromptTimeout <= TimeSpan.Zero || PromptTimeout > MaximumPromptTimeout)
        {
            throw new ArgumentOutOfRangeException(nameof(PromptTimeout), "The Secret Service prompt timeout must be positive and at most thirty minutes.");
        }

        if (BusAddress is not null && (BusAddress.Length == 0 || BusAddress.Contains('\0', StringComparison.Ordinal)))
        {
            throw new ArgumentException("The D-Bus address must be null or a non-empty address.", nameof(BusAddress));
        }
    }
}

/// <summary>
/// The recorded outcome of selecting the platform secret store: the store, which backend it is and the protection it gives.
/// The node keeps this record and shows <see cref="CredentialInOsStore"/> as <c>AccountStatus.credential_in_os_store</c>.
/// </summary>
public sealed class SecretStoreSelection
{
    internal SecretStoreSelection(ISecretBackingStore store, SecretStoreBackend backend, SecretStoreProtection protection,
        string? fallbackReason)
    {
        Store = store;
        Backend = backend;
        Protection = protection;
        FallbackReason = fallbackReason;
    }

    /// <summary>The selected store.</summary>
    public ISecretBackingStore Store { get; }

    /// <summary>The selected backend.</summary>
    public SecretStoreBackend Backend { get; }

    /// <summary>How the selected store protects values at rest.</summary>
    public SecretStoreProtection Protection { get; }

    /// <summary>Whether credentials are held by the OS secret store (<c>AccountStatus.credential_in_os_store</c>).</summary>
    public bool CredentialInOsStore => Protection == SecretStoreProtection.OsSecretStore;

    /// <summary>Why the OS secret store was not selected; <see langword="null"/> when it was. Contains no secret material.</summary>
    public string? FallbackReason { get; }
}

/// <summary>Selection of the platform secret store (secure storage is the one fatal slot, DG-04).</summary>
public static class OsSecretStore
{
    /// <summary>
    /// Returns the OS secret-store adapter of the current platform: Windows Credential Manager, or on Linux the Secret Service
    /// of the session bus when it is available. Otherwise throws <see cref="PlatformNotSupportedException"/>. It never falls back
    /// to files, preferences, environment variables or memory; the reported file fallback is chosen only by
    /// <see cref="SelectForCurrentPlatform"/>.
    /// </summary>
    public static ISecretBackingStore CreateForCurrentPlatform() => Create(OperatingSystem.IsWindows());

    /// <summary>
    /// Selects the node's credential store and records the choice. Windows: Credential Manager. Linux: the Secret Service when the
    /// session bus and <c>org.freedesktop.secrets</c> are available, otherwise one 0600 file per secret under
    /// <c>&lt;dataRoot&gt;/run/secrets/</c> with <see cref="SecretStoreProtection.FileOwnerOnly"/>, which the caller reports as weaker
    /// storage. Other platforms throw <see cref="PlatformNotSupportedException"/>.
    /// </summary>
    /// <param name="dataRoot">The absolute node data root that owns the <c>run/secrets</c> fallback directory.</param>
    /// <param name="options">Secret Service options; <see langword="null"/> uses the session bus of the environment.</param>
    public static SecretStoreSelection SelectForCurrentPlatform(string dataRoot, SecretServiceOptions? options = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataRoot);
        if (OperatingSystem.IsWindows())
        {
            return new SecretStoreSelection(new WindowsCredentialManagerSecretStore(), SecretStoreBackend.WindowsCredentialManager,
                SecretStoreProtection.OsSecretStore, fallbackReason: null);
        }

        if (OperatingSystem.IsLinux())
        {
            var linuxOptions = options ?? new SecretServiceOptions();
            linuxOptions.Validate();
            return SelectLinux(dataRoot, linuxOptions, linuxOptions.BusAddress ?? SecretServiceSecretStore.ResolveSessionBusAddress());
        }

        throw new PlatformNotSupportedException("No validated secret store exists for this platform.");
    }

    /// <summary>The Linux selection with the session bus address already resolved (<see langword="null"/>: no session bus).</summary>
    [SupportedOSPlatform("linux")]
    internal static SecretStoreSelection SelectLinux(string dataRoot, SecretServiceOptions options, string? sessionBusAddress)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        // The fallback validates the data root first, so an invalid root fails the same way whichever backend is chosen.
        var fallback = new OwnerOnlyFileSecretStore(dataRoot);
        if (SecretServiceSecretStore.TryOpen(sessionBusAddress, options, out var service, out string? reason))
        {
            return new SecretStoreSelection(service, SecretStoreBackend.SecretService, SecretStoreProtection.OsSecretStore,
                fallbackReason: null);
        }

        return new SecretStoreSelection(fallback, SecretStoreBackend.OwnerOnlyFile, SecretStoreProtection.FileOwnerOnly, reason);
    }

    internal static ISecretBackingStore Create(bool isWindows, SecretServiceOptions? options = null)
    {
        if (isWindows && OperatingSystem.IsWindows()) return new WindowsCredentialManagerSecretStore();
        if (!isWindows && OperatingSystem.IsLinux())
        {
            var linuxOptions = options ?? new SecretServiceOptions();
            linuxOptions.Validate();
            if (SecretServiceSecretStore.TryOpen(linuxOptions, out var store, out _)) return store;
        }

        throw new PlatformNotSupportedException(
            "No validated OS secret-store adapter is available on this platform; the application must not start without protected storage.");
    }
}

/// <summary>Key and value rules shared by the Linux backends, so a key or value valid for one backend is valid for all.</summary>
internal static class SecretStoreKey
{
    internal const int MaximumLength = 128;

    /// <summary>
    /// A key is 1–128 characters of <c>[A-Za-z0-9._-]</c> that starts with a letter or digit, so it is also a safe single file
    /// name (never empty, <c>.</c>, <c>..</c>, hidden or containing a separator). The broker's canonical opaque targets qualify.
    /// </summary>
    internal static void Validate(string key, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(key, parameterName);
        if (key.Length is 0 or > MaximumLength || !char.IsAsciiLetterOrDigit(key[0]))
        {
            throw new ArgumentException("A secret key is 1-128 characters and starts with an ASCII letter or digit.", parameterName);
        }

        foreach (char character in key)
        {
            if (!char.IsAsciiLetterOrDigit(character) && character is not ('.' or '_' or '-'))
            {
                throw new ArgumentException("A secret key contains only ASCII letters, digits, '.', '_' and '-'.", parameterName);
            }
        }
    }

    internal static void ValidateValue(ReadOnlySpan<byte> secret, string parameterName)
    {
        if (secret.IsEmpty || secret.Length > SecretBroker.MaximumSecretBytes)
        {
            throw new ArgumentOutOfRangeException(parameterName, "Secret values must be non-empty and within the OS credential-store bound.");
        }
    }
}
