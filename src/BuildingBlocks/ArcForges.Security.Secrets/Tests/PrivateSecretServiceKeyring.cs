// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace ArcForges.Security.Secrets.Tests;

/// <summary>
/// A private session bus and, optionally, a private unlocked GNOME Keyring that exist only for one test. Both run as children of the
/// test process with an environment that names only a new temporary directory: their own bus socket, HOME, XDG data, config, cache
/// and runtime directories (so the keyring files and the keyring control socket are new). They never see the user's session bus,
/// keyring daemon or keyring files, and are killed and deleted when the test ends. The keyring password is random and test-only.
/// The bus configuration lists no service directories, so nothing on it is D-Bus activated.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed class PrivateSecretServiceKeyring : IDisposable
{
    private static readonly TimeSpan StartTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan ToolTimeout = TimeSpan.FromSeconds(30);
    private readonly Process _bus;
    private readonly Process? _keyring;
    private readonly StringBuilder _keyringOutput = new();

    private PrivateSecretServiceKeyring(string root, Process bus, string address, Process? keyring)
    {
        Root = root;
        _bus = bus;
        Address = address;
        _keyring = keyring;
    }

    /// <summary>The temporary directory that holds the bus socket, the keyring files and every runtime directory.</summary>
    public string Root { get; }

    /// <summary>The private bus address (a socket inside <see cref="Root"/>).</summary>
    public string Address { get; }

    /// <summary>Options that reach only this private bus, with short bounds for tests.</summary>
    public SecretServiceOptions Options => new()
    {
        BusAddress = Address,
        CallTimeout = TimeSpan.FromSeconds(10),
        PromptTimeout = TimeSpan.FromSeconds(10),
    };

    /// <summary>Skips the calling test, with the reason, when a tool the private keyring needs is not installed.</summary>
    public static void RequireTools(params string[] tools)
    {
        foreach (string tool in tools)
        {
            if (Find(tool) is null)
            {
                Assert.Skip($"'{tool}' is not installed in this environment, so the private Secret Service cannot be started "
                    + "(user-installed packages, acceptance register H-11: gnome-keyring, dbus-daemon, libsecret-tools).");
            }
        }
    }

    /// <summary>
    /// Starts a private bus, and with <paramref name="withKeyring"/> a private GNOME Keyring. With <paramref name="unlock"/> the keyring
    /// creates and unlocks its login keyring from a random password (the default collection); without it the keyring starts like a
    /// headless session in a fresh home: no login keyring and no default collection.
    /// </summary>
    public static PrivateSecretServiceKeyring Start(bool withKeyring, bool unlock = true)
    {
        RequireTools(withKeyring ? ["dbus-daemon", "gnome-keyring-daemon"] : ["dbus-daemon"]);
        var root = Directory.CreateTempSubdirectory("afss-");
        File.SetUnixFileMode(root.FullName, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        foreach (string name in new[] { "home", "data", "config", "cache", "run" })
        {
            Directory.CreateDirectory(Path.Combine(root.FullName, name),
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        string socket = Path.Combine(root.FullName, "bus");
        string configuration = Path.Combine(root.FullName, "bus.conf");
        File.WriteAllText(configuration, $"""
            <!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
            <busconfig>
              <type>session</type>
              <listen>unix:path={socket}</listen>
              <auth>EXTERNAL</auth>
              <policy context="default">
                <allow send_destination="*" eavesdrop="true"/>
                <allow eavesdrop="true"/>
                <allow own="*"/>
              </policy>
            </busconfig>
            """);

        Process? bus = null;
        Process? keyring = null;
        try
        {
            var busStart = Isolated(root.FullName, Find("dbus-daemon")!, address: null);
            busStart.ArgumentList.Add("--config-file=" + configuration);
            busStart.ArgumentList.Add("--nofork");
            busStart.ArgumentList.Add("--print-address=1");
            busStart.RedirectStandardOutput = true;
            busStart.RedirectStandardError = true;
            bus = Process.Start(busStart) ?? throw new InvalidOperationException("dbus-daemon did not start.");
            bus.ErrorDataReceived += (_, _) => { };
            bus.BeginErrorReadLine();
            var line = bus.StandardOutput.ReadLineAsync();
            if (!line.Wait(StartTimeout) || string.IsNullOrWhiteSpace(line.Result))
            {
                throw new InvalidOperationException("The private dbus-daemon did not report its address.");
            }

            string address = line.Result.Trim();
            if (!address.StartsWith("unix:path=" + socket, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("The private dbus-daemon listens somewhere else than its own socket.");
            }

            PrivateSecretServiceKeyring session;
            if (withKeyring)
            {
                var keyringStart = Isolated(root.FullName, Find("gnome-keyring-daemon")!, address);
                keyringStart.ArgumentList.Add("--foreground");
                if (unlock) keyringStart.ArgumentList.Add("--unlock");
                keyringStart.ArgumentList.Add("--components=secrets");
                keyringStart.RedirectStandardInput = unlock;
                keyringStart.RedirectStandardOutput = true;
                keyringStart.RedirectStandardError = true;
                keyring = Process.Start(keyringStart) ?? throw new InvalidOperationException("gnome-keyring-daemon did not start.");
                session = new PrivateSecretServiceKeyring(root.FullName, bus, address, keyring);
                keyring.OutputDataReceived += (_, data) => session.Record(data.Data);
                keyring.ErrorDataReceived += (_, data) => session.Record(data.Data);
                keyring.BeginOutputReadLine();
                keyring.BeginErrorReadLine();
                if (unlock)
                {
                    // --unlock reads the password of the new private login keyring from standard input until it closes.
                    keyring.StandardInput.Write(Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(24)));
                    keyring.StandardInput.Close();
                }

                session.WaitForSecretService();
            }
            else
            {
                session = new PrivateSecretServiceKeyring(root.FullName, bus, address, keyring: null);
            }

            return session;
        }
        catch
        {
            Stop(keyring);
            Stop(bus);
            DeleteTree(root.FullName);
            throw;
        }
    }

    /// <summary>Runs <c>secret-tool</c> (libsecret, an independent Secret Service client) against this private bus only.</summary>
    public (int ExitCode, byte[] Output) SecretTool(byte[]? input, params string[] arguments)
    {
        var start = Isolated(Root, Find("secret-tool") ?? throw new InvalidOperationException("secret-tool is not installed."), Address);
        foreach (string argument in arguments) start.ArgumentList.Add(argument);
        return RunTool(start, input);
    }

    /// <summary>Runs <c>dbus-send</c> against this private bus only.</summary>
    public (int ExitCode, byte[] Output) DBusSend(params string[] arguments)
    {
        var start = Isolated(Root, Find("dbus-send") ?? throw new InvalidOperationException("dbus-send is not installed."), Address);
        start.ArgumentList.Add("--session");
        start.ArgumentList.Add("--print-reply");
        foreach (string argument in arguments) start.ArgumentList.Add(argument);
        return RunTool(start, input: null);
    }

    public void Dispose()
    {
        Stop(_keyring);
        Stop(_bus);
        DeleteTree(Root);
    }

    public static string? Find(string tool)
    {
        foreach (string directory in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(':')
            .Append("/usr/bin").Append("/bin"))
        {
            if (directory.Length == 0) continue;
            string candidate = Path.Combine(directory, tool);
            if (File.Exists(candidate)) return candidate;
        }

        return null;
    }

    private void Record(string? line)
    {
        if (line is null) return;
        lock (_keyringOutput) _keyringOutput.AppendLine(line);
    }

    private void WaitForSecretService()
    {
        var deadline = Stopwatch.StartNew();
        string? reason = null;
        while (deadline.Elapsed < StartTimeout)
        {
            if (_keyring!.HasExited) break;
            // Ready when the service answers: with a default collection, or (a keyring started without --unlock) without one.
            if (SecretServiceSecretStore.TryOpen(Address, Options, out _, out reason)
                || reason.Contains("no default collection", StringComparison.Ordinal))
            {
                return;
            }

            Thread.Sleep(100);
        }

        string output;
        lock (_keyringOutput) output = _keyringOutput.ToString();
        throw new InvalidOperationException($"The private gnome-keyring-daemon did not provide the Secret Service ({reason}). Output: {output}");
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

    private static (int ExitCode, byte[] Output) RunTool(ProcessStartInfo start, byte[]? input)
    {
        start.RedirectStandardInput = true;
        start.RedirectStandardOutput = true;
        start.RedirectStandardError = true;
        using var process = Process.Start(start) ?? throw new InvalidOperationException(start.FileName + " did not start.");
        process.ErrorDataReceived += (_, _) => { };
        process.BeginErrorReadLine();
        var standardOutput = process.StandardOutput.BaseStream;
        var copy = Task.Run(() =>
        {
            using var buffer = new MemoryStream();
            standardOutput.CopyTo(buffer);
            return buffer.ToArray();
        });
        if (input is not null) process.StandardInput.BaseStream.Write(input);
        process.StandardInput.Close();
        if (!process.WaitForExit(ToolTimeout) || !copy.Wait(ToolTimeout))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException(start.FileName + " did not finish within its bound.");
        }

        return (process.ExitCode, copy.Result);
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

    private static void DeleteTree(string root)
    {
        try
        {
            Directory.Delete(root, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
