// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Security.Secrets;

/// <summary>
/// The runtime tripwire of the OS secret-store test guard (ArcForges-Design 16-testing-strategy §1, guard item 2). Every test
/// project sets the AppContext switch <see cref="DenyOsStoresSwitch"/> in its runtime configuration. While it is set, the real OS
/// secret stores of the user (the Windows Credential Manager always, the Secret Service on the user's session bus) are refused
/// with <see cref="OsSecretStoreDeniedException"/> before any OS call, unless <see cref="OptInVariable"/> is exactly <c>1</c>,
/// which only the OS secret-store integration tier sets. Release builds never set the switch, so production is unchanged.
/// </summary>
public static class OsSecretStoreGuard
{
    /// <summary>The AppContext switch that test processes set to deny the real OS secret stores.</summary>
    public const string DenyOsStoresSwitch = "ArcForges.Security.Secrets.DenyOsStores";

    /// <summary>The single opt-in of the OS secret-store integration tier; only the value <c>1</c> lifts the tripwire.</summary>
    public const string OptInVariable = "ARCFORGES_OS_SECRET_STORE_TESTS";

    /// <summary>Whether this process refuses the real OS secret stores now (the switch is set and the opt-in is not).</summary>
    public static bool IsDenied => IsDeniedBy(DenySwitch(), Environment.GetEnvironmentVariable(OptInVariable));

    /// <summary>
    /// Throws <see cref="OsSecretStoreDeniedException"/> when <see cref="IsDenied"/>. Call it before any OS call that reaches a
    /// store of the user that the tripwire covers (for example a CNG user key store), so every guarded path fails the same way.
    /// </summary>
    /// <param name="store">The refused store, for the message (for example "the Windows Credential Manager").</param>
    public static void ThrowIfDenied(string store)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(store);
        if (IsDenied) throw new OsSecretStoreDeniedException(Message(store));
    }

    /// <summary>The decision itself: denied when the switch is true and the opt-in is not exactly <c>1</c>.</summary>
    internal static bool IsDeniedBy(bool? denySwitch, string? optIn) => denySwitch == true && optIn != "1";

    internal static string Message(string store) =>
        "ArcForges.Security.Secrets refused to reach " + store + ": this process denies the real OS secret stores (AppContext switch "
        + DenyOsStoresSwitch + "=true, set by every test project) and " + OptInVariable + "=1 is not set. Routine tests use an "
        + "isolated secret-store backend; only the OS secret-store integration tier reaches a real store "
        + "(ArcForges-Design docs/architecture/16-testing-strategy.md section 1).";

    /// <summary>Refuses the Secret Service when <paramref name="explicitAddress"/> or <paramref name="address"/> is the user's session bus.</summary>
    internal static void ThrowIfSecretServiceDenied(string? explicitAddress, string? address)
    {
        if (!IsDenied) return;
        if (explicitAddress is null || IsUserSessionBus(explicitAddress) || (address is not null && IsUserSessionBus(address)))
        {
            throw new OsSecretStoreDeniedException(Message("the Secret Service on the user's session bus"));
        }
    }

    /// <summary>Whether <paramref name="address"/> is in the tripwire's Secret Service scope, read from this process.</summary>
    internal static bool IsUserSessionBus(string address) => IsUserSessionBus(address,
        Environment.GetEnvironmentVariable("DBUS_SESSION_BUS_ADDRESS"), Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR"),
        OperatingSystem.IsLinux() ? LinuxFileSystemNative.EffectiveUserId : null, Path.GetTempPath());

    /// <summary>
    /// The Secret Service scope. Only a bus that a test supplies explicitly and owns is outside it: a single
    /// <c>unix:path=</c> socket that is not the user's session bus and that either does not exist or lies in a directory of its
    /// own under the temporary directory (a private daemon). Everything else is the user's session bus or cannot be shown not to be:
    /// the <c>DBUS_SESSION_BUS_ADDRESS</c> value or a path in it, <c>/run/user/&lt;uid&gt;/bus</c>, <c>$XDG_RUNTIME_DIR/bus</c>,
    /// abstract, TCP, launchd or escaped addresses, address lists, and existing sockets elsewhere.
    /// </summary>
    internal static bool IsUserSessionBus(string address, string? sessionBusVariable, string? runtimeDirectory, uint? userId,
        string temporaryDirectory)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentException.ThrowIfNullOrEmpty(temporaryDirectory);
        string trimmed = address.Trim();
        if (!string.IsNullOrWhiteSpace(sessionBusVariable)
            && (string.Equals(trimmed, sessionBusVariable.Trim(), StringComparison.Ordinal)
                || sessionBusVariable.Split(';').Any(entry => string.Equals(trimmed, entry.Trim(), StringComparison.Ordinal))))
        {
            return true;
        }

        string? path = SocketPath(trimmed);
        if (path is null) return true;
        var userBuses = new List<string>();
        if (userId is { } uid) userBuses.Add("/run/user/" + uid.ToString(System.Globalization.CultureInfo.InvariantCulture) + "/bus");
        if (!string.IsNullOrEmpty(runtimeDirectory) && runtimeDirectory.StartsWith('/')) userBuses.Add(Path.Join(runtimeDirectory, "bus"));
        if (!string.IsNullOrWhiteSpace(sessionBusVariable))
        {
            foreach (string entry in sessionBusVariable.Split(';'))
            {
                if (SocketPath(entry.Trim()) is { } sessionPath) userBuses.Add(sessionPath);
            }
        }

        string normalized = Normalize(path);
        if (userBuses.Any(bus => string.Equals(Normalize(bus), normalized, StringComparison.Ordinal))) return true;
        if (!File.Exists(normalized) && !Directory.Exists(normalized)) return false;
        string temporary = Normalize(temporaryDirectory);
        string? parent = Path.GetDirectoryName(normalized);
        return parent is null || string.Equals(parent, temporary, StringComparison.Ordinal)
            || !normalized.StartsWith(temporary + "/", StringComparison.Ordinal);
    }

    /// <summary>The socket path of a single <c>unix:path=</c> address (other keys allowed, such as <c>guid</c>); otherwise null.</summary>
    private static string? SocketPath(string address)
    {
        const string Prefix = "unix:";
        if (!address.StartsWith(Prefix, StringComparison.Ordinal) || address.Contains(';', StringComparison.Ordinal)
            || address.Contains('%', StringComparison.Ordinal))
        {
            return null;
        }

        string? path = null;
        foreach (string pair in address[Prefix.Length..].Split(','))
        {
            int equals = pair.IndexOf('=', StringComparison.Ordinal);
            if (equals <= 0) return null;
            string key = pair[..equals];
            if (key is "abstract" or "dir" or "tmpdir" or "runtime") return null;
            if (key == "path")
            {
                if (path is not null) return null;
                path = pair[(equals + 1)..];
            }
        }

        return path is { Length: > 1 } && path.StartsWith('/') ? path : null;
    }

    private static string Normalize(string path)
    {
        string full = path.Replace('\\', '/');
        var parts = new List<string>();
        foreach (string part in full.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            if (part == ".") continue;
            if (part == "..")
            {
                if (parts.Count > 0) parts.RemoveAt(parts.Count - 1);
                continue;
            }

            parts.Add(part);
        }

        return "/" + string.Join('/', parts);
    }

    private static bool? DenySwitch() => AppContext.TryGetSwitch(DenyOsStoresSwitch, out bool enabled) ? enabled : null;
}

/// <summary>
/// The guard's error: a test process tried to reach a real OS secret store of the user without the OS secret-store tier's opt-in
/// (<see cref="OsSecretStoreGuard"/>). It is never an "unavailable backend": selection propagates it and never falls back.
/// </summary>
public sealed class OsSecretStoreDeniedException : InvalidOperationException
{
    /// <summary>Creates the error with the default message.</summary>
    public OsSecretStoreDeniedException()
        : base(OsSecretStoreGuard.Message("a real OS secret store"))
    {
    }

    /// <summary>Creates the error with a message.</summary>
    public OsSecretStoreDeniedException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the error with a message and the error that caused it.</summary>
    public OsSecretStoreDeniedException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
