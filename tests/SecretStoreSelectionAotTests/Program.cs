// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Security.Secrets;

// Native AOT probe of the ArcForges.Security.Secrets platform selection (AF-DP-02). See README.md.
if (RuntimeFeature.IsDynamicCodeSupported)
{
    Console.Error.WriteLine("FAIL: run the Native AOT executable, not the JIT-compiled assembly.");
    return 1;
}

try
{
    if (OperatingSystem.IsWindows())
    {
        // Like every test project, the probe's runtime configuration sets the OS secret-store test tripwire, so the selection is
        // refused before any OS call and the probe never reaches the user's Credential Manager. This proves that the AppContext
        // switch and the refusal survive Native AOT; the Windows selection itself is asserted by the OS secret-store tier.
        try
        {
            _ = OsSecretStore.SelectForCurrentPlatform(Path.Combine(Path.GetTempPath(), "arcforges-secrets-aot-unused"));
        }
        catch (OsSecretStoreDeniedException)
        {
            Console.WriteLine("PASS: windows selection refused by the test tripwire before any OS call (nothing read or written)");
            return 0;
        }

        Console.Error.WriteLine("FAIL: the Windows selection was not refused by the test tripwire.");
        return 1;
    }

    if (!OperatingSystem.IsLinux())
    {
        Console.Error.WriteLine("FAIL: only Windows and Linux are supported (macOS is not claimed, P2-023).");
        return 1;
    }

    LinuxProbe.FileFallback();
    if (args.Length == 1 && args[0] == "--private-keyring")
    {
        LinuxProbe.PrivateSecretService();
    }
    else
    {
        Console.WriteLine("SKIP: Secret Service (pass --private-keyring to start a private dbus-daemon and gnome-keyring-daemon)");
    }

    return 0;
}
catch (InvalidOperationException failure)
{
    Console.Error.WriteLine("FAIL: " + failure.Message);
    return 1;
}

[SupportedOSPlatform("linux")]
internal static class LinuxProbe
{
    private const UnixFileMode Mode0700 = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode Mode0600 = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    /// <summary>The file fallback, selected because the configured bus does not exist.</summary>
    public static void FileFallback()
    {
        var root = Directory.CreateTempSubdirectory("afsaot-");
        try
        {
            string dataRoot = Path.Combine(root.FullName, "data");
            var selection = OsSecretStore.SelectForCurrentPlatform(dataRoot, new SecretServiceOptions
            {
                BusAddress = "unix:path=" + Path.Combine(root.FullName, "no-bus"),
                CallTimeout = TimeSpan.FromSeconds(5),
            });
            Expect(selection.Backend == SecretStoreBackend.OwnerOnlyFile, "the fallback is selected without a bus");
            Expect(selection.Protection == SecretStoreProtection.FileOwnerOnly && !selection.CredentialInOsStore,
                "the fallback reports FileOwnerOnly");
            Expect(!string.IsNullOrEmpty(selection.FallbackReason), "the fallback records why");
            RoundTrip(selection.Store, "node-credential");
            selection.Store.Write("node-data-key", RandomNumberGenerator.GetBytes(32));
            string directory = Path.Combine(dataRoot, "run", "secrets");
            Expect(File.GetUnixFileMode(directory) == Mode0700, "the secret directory is 0700");
            Expect(File.GetUnixFileMode(Path.Combine(directory, "node-data-key")) == Mode0600, "a secret file is 0600");
            Expect(Directory.GetFileSystemEntries(directory).Length == 1, "only the remaining secret file exists");
            Console.WriteLine("PASS: linux file fallback OwnerOnlyFile/FileOwnerOnly (0700 directory, 0600 file, atomic replace, read, delete)");
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    /// <summary>The Secret Service, against a private bus and an unlocked private GNOME Keyring that exist only for this run.</summary>
    public static void PrivateSecretService()
    {
        string? busDaemon = Find("dbus-daemon");
        string? keyringDaemon = Find("gnome-keyring-daemon");
        if (busDaemon is null || keyringDaemon is null)
        {
            Console.WriteLine("SKIP: Secret Service (dbus-daemon or gnome-keyring-daemon is not installed; user installs, H-11)");
            return;
        }

        var root = Directory.CreateTempSubdirectory("afsaot-");
        Process? bus = null;
        Process? keyring = null;
        try
        {
            File.SetUnixFileMode(root.FullName, Mode0700);
            foreach (string name in new[] { "home", "data", "config", "cache", "run" })
            {
                Directory.CreateDirectory(Path.Combine(root.FullName, name), Mode0700);
            }

            string socket = Path.Combine(root.FullName, "bus");
            string configuration = Path.Combine(root.FullName, "bus.conf");
            File.WriteAllText(configuration,
                "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\" "
                + "\"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n<busconfig><type>session</type>"
                + "<listen>unix:path=" + socket + "</listen><auth>EXTERNAL</auth><policy context=\"default\">"
                + "<allow send_destination=\"*\" eavesdrop=\"true\"/><allow eavesdrop=\"true\"/><allow own=\"*\"/></policy></busconfig>\n");
            var busStart = Isolated(root.FullName, busDaemon, address: null);
            busStart.ArgumentList.Add("--config-file=" + configuration);
            busStart.ArgumentList.Add("--nofork");
            busStart.ArgumentList.Add("--print-address=1");
            busStart.RedirectStandardOutput = true;
            bus = Process.Start(busStart) ?? throw new InvalidOperationException("dbus-daemon did not start");
            var line = bus.StandardOutput.ReadLineAsync();
            Expect(line.Wait(TimeSpan.FromSeconds(15)) && line.Result is not null, "the private bus reports its address");
            string address = line.Result!.Trim();
            Expect(address.StartsWith("unix:path=" + socket, StringComparison.Ordinal), "the private bus listens on its own socket");

            var keyringStart = Isolated(root.FullName, keyringDaemon, address);
            keyringStart.ArgumentList.Add("--foreground");
            keyringStart.ArgumentList.Add("--unlock");
            keyringStart.ArgumentList.Add("--components=secrets");
            keyringStart.RedirectStandardInput = true;
            keyringStart.RedirectStandardOutput = true;
            keyringStart.RedirectStandardError = true;
            keyring = Process.Start(keyringStart) ?? throw new InvalidOperationException("gnome-keyring-daemon did not start");
            keyring.OutputDataReceived += (_, _) => { };
            keyring.ErrorDataReceived += (_, _) => { };
            keyring.BeginOutputReadLine();
            keyring.BeginErrorReadLine();
            keyring.StandardInput.Write(Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(24))); // test-only password
            keyring.StandardInput.Close();

            var options = new SecretServiceOptions
            {
                BusAddress = address,
                CallTimeout = TimeSpan.FromSeconds(10),
                PromptTimeout = TimeSpan.FromSeconds(10),
            };
            string dataRoot = Path.Combine(root.FullName, "node-data");
            SecretStoreSelection? selection = null;
            var waited = Stopwatch.StartNew();
            while (waited.Elapsed < TimeSpan.FromSeconds(15) && !keyring.HasExited)
            {
                selection = OsSecretStore.SelectForCurrentPlatform(dataRoot, options);
                if (selection.Backend == SecretStoreBackend.SecretService) break;
                Thread.Sleep(100);
            }

            string selected = "the private Secret Service is selected: " + (selection?.FallbackReason ?? "no selection");
            Expect(selection is { Backend: SecretStoreBackend.SecretService }, selected);
            Expect(selection.Protection == SecretStoreProtection.OsSecretStore && selection.CredentialInOsStore
                && selection.FallbackReason is null, "the Secret Service reports the OS store");
            RoundTrip(selection.Store, "node-credential-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(4)));
            Expect(!Directory.Exists(Path.Combine(dataRoot, "run")), "the file fallback was not touched");
            Console.WriteLine("PASS: linux Secret Service SecretService/OsSecretStore on a private gnome-keyring (write, read, replace, delete)");
        }
        finally
        {
            Stop(keyring);
            Stop(bus);
            root.Delete(recursive: true);
        }
    }

    private static void RoundTrip(ISecretBackingStore store, string key)
    {
        byte[] first = Encoding.ASCII.GetBytes(Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32)));
        byte[] second = Encoding.ASCII.GetBytes(Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(40)));
        Expect(store.Read(key) is null, "a new key reads as absent");
        store.Write(key, first);
        Expect(store.Read(key) is { } read1 && read1.AsSpan().SequenceEqual(first), "the value reads back");
        store.Write(key, second);
        Expect(store.Read(key) is { } read2 && read2.AsSpan().SequenceEqual(second), "the replaced value reads back");
        Expect(store.Delete(key) && store.Read(key) is null && !store.Delete(key), "the value is deleted once");
    }

    private static ProcessStartInfo Isolated(string root, string executable, string? address)
    {
        var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true };
        start.Environment.Clear();
        start.Environment["PATH"] = "/usr/bin:/bin";
        start.Environment["LANG"] = "C.UTF-8";
        start.Environment["HOME"] = Path.Combine(root, "home");
        start.Environment["XDG_DATA_HOME"] = Path.Combine(root, "data");
        start.Environment["XDG_CONFIG_HOME"] = Path.Combine(root, "config");
        start.Environment["XDG_CACHE_HOME"] = Path.Combine(root, "cache");
        start.Environment["XDG_RUNTIME_DIR"] = Path.Combine(root, "run");
        if (address is not null) start.Environment["DBUS_SESSION_BUS_ADDRESS"] = address;
        return start;
    }

    private static string? Find(string tool)
    {
        foreach (string directory in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(':').Append("/usr/bin"))
        {
            if (directory.Length > 0 && File.Exists(Path.Combine(directory, tool))) return Path.Combine(directory, tool);
        }

        return null;
    }

    private static void Stop(Process? process)
    {
        if (process is null) return;
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(TimeSpan.FromSeconds(10));
            }
        }
        catch (InvalidOperationException)
        {
        }
        finally
        {
            process.Dispose();
        }
    }

    private static void Expect([DoesNotReturnIf(false)] bool condition, string what)
    {
        if (!condition) throw new InvalidOperationException(what);
    }
}
