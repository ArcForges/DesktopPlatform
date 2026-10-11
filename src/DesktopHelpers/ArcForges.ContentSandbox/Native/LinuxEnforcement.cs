// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using ArcForges.ContentSandbox.Contracts;
using ArcForges.ContentSandbox.Host;

namespace ArcForges.ContentSandbox.Native;

/// <summary>
/// The Linux profile of annex 24, applied by the helper to itself before it serves anything: no_new_privs, resource limits, a Landlock
/// ruleset that handles every file-system right and allows only a short read-only list, and a seccomp filter synchronised to every thread (Landlock too, with its own TSYNC flag; a kernel that refuses it ends the profile). It is
/// then verified by attempting what it must deny. A kernel without Landlock, a processor without a table, or any attempt that is not denied makes
/// the helper refuse to run a parser (exit code 70). Each refusing step writes one bounded line to the diagnostic stream, named from the closed
/// list in <see cref="LinuxProfileSteps"/> with the observed error number and nothing else (no path, no frame content), as the Windows
/// self-check names the attempt that was not denied; the line does not change the refusal. It has not been run on Linux by the task that wrote
/// it: only its pure parts are tested offline.
/// </summary>
[SupportedOSPlatform("linux")]
internal static class LinuxEnforcement
{
    private const int SeccompSetModeFilter = 1;
    private const uint SeccompFilterTsync = 1;
    private const int LandlockCreateRuleset = 444;
    private const int LandlockAddRule = 445;
    private const int LandlockRestrictSelf = 446;
    private const int LandlockRulePathBeneath = 1;
    private const int LandlockRestrictSelfTsync = 1 << 3;
    private const int OpenPath = 0x200000;
    private const int OpenCloseOnExec = 0x80000;
    private const int AtFdCwd = -100;
    private const ulong DataSlackBytes = 128UL * 1024 * 1024;

    /// <summary>Puts the profile in force and checks it; false means the helper must not run a parser.</summary>
    internal static bool ApplyAndVerify(ContentSandboxLaunchFrame frame)
    {
        ArgumentNullException.ThrowIfNull(frame);
        if (!OperatingSystem.IsLinux())
        {
            return false;
        }

        // The writer is created before any restriction, so reporting a refusal never needs a call the profile denies.
        var diagnostics = Console.Error;
        var architecture = SeccompProgram.Current;
        if (architecture == LinuxArchitecture.Unsupported)
        {
            return Refuse(diagnostics, LinuxProfileSteps.Architecture, 0);
        }

        if (LinuxNative.Prctl(LinuxNative.PrSetNoNewPrivs, 1, 0, 0, 0) != 0)
        {
            return Refuse(diagnostics, LinuxProfileSteps.NoNewPrivileges, Marshal.GetLastPInvokeError());
        }

        SetLimits(frame);
        var abi = (int)LinuxNative.Syscall(LandlockCreateRuleset, 0, 0, (nint)LandlockPlan.CreateRulesetVersion, 0, 0);
        if (abi < 1)
        {
            return Refuse(diagnostics, LinuxProfileSteps.LandlockAbi, abi < 0 ? Marshal.GetLastPInvokeError() : 0);
        }

        var (landlockStep, landlockError) = ApplyLandlock(architecture, abi);
        if (landlockStep is not null)
        {
            return Refuse(diagnostics, landlockStep, landlockError);
        }

        if (!ApplySeccomp(architecture))
        {
            return Refuse(diagnostics, LinuxProfileSteps.SeccompTsync, Marshal.GetLastPInvokeError());
        }

        return Verify(architecture, diagnostics);
    }

    private static bool Refuse(TextWriter diagnostics, string step, int error)
    {
        Report(diagnostics, LinuxProfileSteps.Refused(step, error));
        return false;
    }

    /// <summary>Writes one diagnostic line; a stream that cannot take it changes nothing, because the helper refuses either way.</summary>
    private static void Report(TextWriter diagnostics, string line)
    {
        try
        {
            diagnostics.WriteLine(line);
            diagnostics.Flush();
        }
        catch (Exception exception) when (exception is IOException or ObjectDisposedException or UnauthorizedAccessException)
        {
            // The parent reads the exit code; the line is only an attribution.
        }
    }

    private static void SetLimits(ContentSandboxLaunchFrame frame)
    {
        var data = frame.Limits.MaxMemoryBytes + frame.InputLength + frame.SlotCapacities.Aggregate(0UL, (sum, slot) => sum + slot) + DataSlackBytes;
        Limit(LinuxNative.RlimitCore, 0);
        Limit(LinuxNative.RlimitNofile, 256);
        Limit(LinuxNative.RlimitData, data);
    }

    private static void Limit(int resource, ulong value)
    {
        var limit = new LinuxNative.RlimitValue { Current = value, Maximum = value };
        _ = LinuxNative.SetRlimit(resource, ref limit);
    }

    /// <summary>Puts the Landlock ruleset in force; a null step means success, otherwise the refusing step and its error number.</summary>
    private static unsafe (string? Step, int Error) ApplyLandlock(LinuxArchitecture architecture, int abi)
    {
        var handledFileSystem = LandlockPlan.HandledFileSystem(abi);
        var handledNetwork = LandlockPlan.HandledNetwork(abi);
        var attribute = stackalloc ulong[2];
        attribute[0] = handledFileSystem;
        attribute[1] = handledNetwork;
        var size = abi >= 4 ? 16 : 8;
        var ruleset = (int)LinuxNative.Syscall(LandlockCreateRuleset, (nint)attribute, size, 0, 0, 0);
        if (ruleset < 0)
        {
            return (LinuxProfileSteps.LandlockRuleset, Marshal.GetLastPInvokeError());
        }

        try
        {
            var rule = stackalloc byte[12];
            foreach (var (path, directory) in LandlockPlan.ReadOnlyPlaces(AppContext.BaseDirectory.TrimEnd('/')))
            {
                var descriptor = OpenForRule(architecture, path);
                if (descriptor < 0)
                {
                    continue;
                }

                try
                {
                    var allowed = (directory ? LandlockPlan.Execute | LandlockPlan.ReadFile | LandlockPlan.ReadDirectory : LandlockPlan.ReadFile)
                        | (path == "/dev/null" ? LandlockPlan.WriteFile : 0);
                    allowed &= handledFileSystem;
                    *(ulong*)rule = allowed;
                    *(int*)(rule + 8) = descriptor;
                    if (LinuxNative.Syscall(LandlockAddRule, ruleset, LandlockRulePathBeneath, (nint)rule, 0, 0) != 0)
                    {
                        return (LinuxProfileSteps.LandlockRule, Marshal.GetLastPInvokeError());
                    }
                }
                finally
                {
                    _ = CloseDescriptor(descriptor);
                }
            }

            // landlock_restrict_self restricts only the calling thread (and the threads it creates later) unless the TSYNC flag is given. The runtime
            // and thread pool already own threads that serve calls, so without it a parser on such a thread would be unrestricted. A kernel that
            // refuses the flag (EINVAL: no multithread Landlock) makes this fail, and the helper then refuses to run a parser.
            return LinuxNative.Syscall(LandlockRestrictSelf, ruleset, LandlockRestrictSelfTsync, 0, 0, 0) == 0
                ? (null, 0)
                : (LinuxProfileSteps.LandlockTsync, Marshal.GetLastPInvokeError());
        }
        finally
        {
            _ = CloseDescriptor(ruleset);
        }
    }

    private static int OpenForRule(LinuxArchitecture architecture, string path)
    {
        var text = Marshal.StringToCoTaskMemUTF8(path);
        try
        {
            return (int)LinuxNative.Syscall(OpenatNumber(architecture), AtFdCwd, text, OpenPath | OpenCloseOnExec, 0, 0);
        }
        finally
        {
            Marshal.FreeCoTaskMem(text);
        }
    }

    private static int CloseDescriptor(int descriptor) => (int)LinuxNative.Syscall(3, descriptor, 0, 0, 0, 0);

    private static unsafe bool ApplySeccomp(LinuxArchitecture architecture)
    {
        var bytes = SeccompProgram.Serialize(SeccompProgram.Build(architecture));
        var filter = (byte*)NativeMemory.Alloc((nuint)bytes.Length);
        try
        {
            bytes.CopyTo(new Span<byte>(filter, bytes.Length));
            var program = stackalloc byte[16];
            *(ushort*)program = (ushort)(bytes.Length / 8);
            *(nint*)(program + 8) = (nint)filter;
            return LinuxNative.Syscall(SeccompProgram.SeccompCall(architecture), SeccompSetModeFilter, (nint)SeccompFilterTsync, (nint)program, 0, 0) == 0;
        }
        finally
        {
            NativeMemory.Free(filter);
        }
    }

    /// <summary>
    /// Attempts a socket, a program execution, a trace and a read outside the allowlist: every one must be denied. Each attempt that is not
    /// denied as the profile requires is reported on its own line.
    /// </summary>
    [SuppressMessage("Maintainability", "CA1508", Justification = "The results are read after native calls.")]
    private static bool Verify(LinuxArchitecture architecture, TextWriter diagnostics)
    {
        if (LinuxNative.Prctl(LinuxNative.PrGetNoNewPrivs, 0, 0, 0, 0) != 1)
        {
            return Refuse(diagnostics, LinuxProfileSteps.NoNewPrivilegesReadBack, Marshal.GetLastPInvokeError());
        }

        var x64 = architecture == LinuxArchitecture.X64;
        var socket = LinuxNative.Syscall(x64 ? 41 : 198, 2, 1, 0, 0, 0);
        var socketError = Marshal.GetLastPInvokeError();
        var ptrace = LinuxNative.Syscall(x64 ? 101 : 117, 0, 0, 0, 0, 0);
        var ptraceError = Marshal.GetLastPInvokeError();
        var program = Marshal.StringToCoTaskMemUTF8("/proc/self/exe");
        nint execute;
        int executeError;
        try
        {
            execute = LinuxNative.Syscall(x64 ? 59 : 221, program, 0, 0, 0, 0);
            executeError = Marshal.GetLastPInvokeError();
        }
        finally
        {
            Marshal.FreeCoTaskMem(program);
        }

        var denied = true;
        denied &= Denied(diagnostics, LinuxProfileSteps.Socket, socket, socketError, LinuxNative.Eperm);
        denied &= Denied(diagnostics, LinuxProfileSteps.Ptrace, ptrace, ptraceError, LinuxNative.Eperm);
        denied &= Denied(diagnostics, LinuxProfileSteps.Execute, execute, executeError, LinuxNative.Eperm);
        return denied && OpenOutsideIsDeniedOnEveryKindOfThread(architecture, diagnostics);
    }

    /// <summary>True when the attempt failed with the expected error; otherwise reports the step with the error seen (0 when it succeeded).</summary>
    private static bool Denied(TextWriter diagnostics, string step, nint result, int error, int expected)
    {
        if (result == -1 && error == expected)
        {
            return true;
        }

        Report(diagnostics, LinuxProfileSteps.NotDenied(step, result == -1 ? error : 0));
        return false;
    }

    /// <summary>
    /// Landlock is per thread unless synchronised, so the denial is observed from the applying thread, from a thread the runtime created before
    /// the restriction (thread-pool workers, several at once) and from a thread created afterwards. The lines are written by the applying
    /// thread only, after the other threads have answered.
    /// </summary>
    private static bool OpenOutsideIsDeniedOnEveryKindOfThread(LinuxArchitecture architecture, TextWriter diagnostics)
    {
        var own = OpenOutside(architecture);
        if (own != LinuxNative.Eacces)
        {
            Report(diagnostics, LinuxProfileSteps.NotDenied(LinuxProfileSteps.OpenOutside, own));
            return false;
        }

        var pool = new Task<int>[8];
        for (var i = 0; i < pool.Length; i++)
        {
            pool[i] = Task.Run(() => OpenOutside(architecture));
        }

        var fresh = LinuxProfileSteps.NoAnswer;
        var thread = new Thread(() => Volatile.Write(ref fresh, OpenOutside(architecture))) { IsBackground = true };
        thread.Start();
        var finished = thread.Join(5000);
        var poolResult = LinuxNative.Eacces;
        foreach (var task in pool)
        {
            var answer = task.Wait(5000) ? task.Result : LinuxProfileSteps.NoAnswer;
            if (answer != LinuxNative.Eacces && poolResult == LinuxNative.Eacces)
            {
                poolResult = answer;
            }
        }

        var freshResult = finished ? Volatile.Read(ref fresh) : LinuxProfileSteps.NoAnswer;
        if (poolResult != LinuxNative.Eacces)
        {
            Report(diagnostics, LinuxProfileSteps.NotDenied(LinuxProfileSteps.OpenOutsidePool, poolResult));
        }

        if (freshResult != LinuxNative.Eacces)
        {
            Report(diagnostics, LinuxProfileSteps.NotDenied(LinuxProfileSteps.OpenOutsideNewThread, freshResult));
        }

        return poolResult == LinuxNative.Eacces && freshResult == LinuxNative.Eacces;
    }

    /// <summary>Attempts to open a file outside the allowlist; the result is the error number seen, or 0 when the open succeeded.</summary>
    private static int OpenOutside(LinuxArchitecture architecture)
    {
        var outside = Marshal.StringToCoTaskMemUTF8("/etc/passwd");
        try
        {
            var opened = LinuxNative.Syscall(OpenatNumber(architecture), AtFdCwd, outside, 0, 0, 0);
            var error = Marshal.GetLastPInvokeError();
            if (opened >= 0)
            {
                _ = CloseDescriptor((int)opened);
                return 0;
            }

            return error;
        }
        finally
        {
            Marshal.FreeCoTaskMem(outside);
        }
    }

    private static int OpenatNumber(LinuxArchitecture architecture) => architecture == LinuxArchitecture.X64 ? 257 : 56;
}

/// <summary>
/// The closed list of steps of the Linux profile that can refuse, and the only two shapes of diagnostic line the helper writes for them:
/// <c>isolation: &lt;step&gt; refused (&lt;errno&gt;)</c> when a step that puts the profile in force fails, and
/// <c>isolation: &lt;step&gt; was not denied (&lt;errno&gt;)</c> when a self-check attempt is not denied as required (0 when it succeeded,
/// <c>no-answer</c> when a thread did not answer in time). A line carries a step name from this list and a number, nothing else. It is pure, so
/// it is checked offline on any host.
/// </summary>
internal static class LinuxProfileSteps
{
    internal const string Architecture = "seccomp-architecture";
    internal const string NoNewPrivileges = "no-new-privs";
    internal const string LandlockAbi = "landlock-abi";
    internal const string LandlockRuleset = "landlock-ruleset";
    internal const string LandlockRule = "landlock-rule";
    internal const string LandlockTsync = "landlock-tsync";
    internal const string SeccompTsync = "seccomp-tsync";
    internal const string NoNewPrivilegesReadBack = "no-new-privs-readback";
    internal const string Socket = "socket";
    internal const string Ptrace = "ptrace";
    internal const string Execute = "execve";
    internal const string OpenOutside = "open-outside";
    internal const string OpenOutsidePool = "open-outside-pool";
    internal const string OpenOutsideNewThread = "open-outside-new-thread";

    /// <summary>The value a self-check reports for a thread that did not answer within its wait.</summary>
    internal const int NoAnswer = -1;

    /// <summary>The steps that put the profile in force, in the order the helper applies them, ending with the read-back of no_new_privs.</summary>
    internal static IReadOnlyList<string> Applied { get; } =
        [Architecture, NoNewPrivileges, LandlockAbi, LandlockRuleset, LandlockRule, LandlockTsync, SeccompTsync, NoNewPrivilegesReadBack];

    /// <summary>The self-check attempts that must be denied, in the order the helper makes them.</summary>
    internal static IReadOnlyList<string> Probed { get; } = [Socket, Ptrace, Execute, OpenOutside, OpenOutsidePool, OpenOutsideNewThread];

    /// <summary>The line for a step that puts the profile in force and failed.</summary>
    internal static string Refused(string step, int error) =>
        "isolation: " + Known(Applied, step) + " refused (" + Number(error) + ")";

    /// <summary>The line for a self-check attempt that was not denied as required.</summary>
    internal static string NotDenied(string step, int error) =>
        "isolation: " + Known(Probed, step) + " was not denied (" + Number(error) + ")";

    private static string Known(IReadOnlyList<string> steps, string step) =>
        steps.Contains(step, StringComparer.Ordinal) ? step : throw new ArgumentOutOfRangeException(nameof(step), step, "The step is not in the closed list.");

    private static string Number(int error) =>
        error >= 0 ? error.ToString(System.Globalization.CultureInfo.InvariantCulture) : "no-answer";
}
