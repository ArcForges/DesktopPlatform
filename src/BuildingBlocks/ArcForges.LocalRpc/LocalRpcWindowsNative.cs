// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.LocalRpc;

/// <summary>
/// The Windows bindings of service mode (AD-0013, Design 11 §2): the service pipe with its explicit same-user access list and
/// <c>PIPE_REJECT_REMOTE_CLIENTS</c>, and the pipe client's process, start time, token user and image. Every handle is a safe handle that the
/// runtime closes; nothing here keeps a raw handle past one call.
/// </summary>
[SupportedOSPlatform("windows")]
internal static partial class LocalRpcWindowsNative
{
    internal const uint PipeAccessDuplex = 0x00000003;
    internal const uint FileFlagOverlapped = 0x40000000;
    internal const uint FileFlagFirstPipeInstance = 0x00080000;
    internal const uint PipeTypeByte = 0x00000000;
    internal const uint PipeRejectRemoteClients = 0x00000008;
    internal const uint PipeUnlimitedInstances = 255;
    internal const uint ProcessQueryLimitedInformation = 0x1000;
    internal const uint TokenQuery = 0x0008;
    internal const uint StillActive = 259;
    internal const int ErrorInvalidParameter = 87;
    internal const int ErrorAccessDenied = 5;
    internal const int ErrorPipeBusy = 231;

    /// <summary>
    /// <c>GENERIC_READ | GENERIC_WRITE</c> as they map for a pipe: <c>FILE_GENERIC_READ | FILE_GENERIC_WRITE</c>. The write half includes
    /// <c>FILE_CREATE_PIPE_INSTANCE</c> (<c>FILE_APPEND_DATA</c>), which the owner needs to add the further instances of its own pipe.
    /// </summary>
    internal const PipeAccessRights GenericReadWrite = PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance | PipeAccessRights.Synchronize;

    /// <summary>
    /// The access list of a service pipe: owner and only allowed principal the current user, <c>SYSTEM</c> allowed, <c>NT AUTHORITY\NETWORK</c>
    /// explicitly denied, no inherited entry.
    /// </summary>
    internal static PipeSecurity ServicePipeSecurity()
    {
        using var current = WindowsIdentity.GetCurrent();
        var user = current.User ?? throw new InvalidOperationException("The current token has no user SID.");
        var security = new PipeSecurity();
        security.SetOwner(user);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(user, GenericReadWrite, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), GenericReadWrite, AccessControlType.Allow));
        return security;
    }

    /// <summary>
    /// Creates one instance of a service pipe: duplex, overlapped, byte mode, <c>PIPE_REJECT_REMOTE_CLIENTS</c> and the access list of
    /// <see cref="ServicePipeSecurity"/>. The first instance uses <c>FILE_FLAG_FIRST_PIPE_INSTANCE</c>, so binding fails when the name exists.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the handle passes to the returned pipe stream; Wrap disposes it if construction fails.")]
    internal static unsafe NamedPipeServerStream CreateServicePipe(string name, bool first, uint rejectFlag = PipeRejectRemoteClients, PipeSecurity? security = null)
    {
        var descriptor = (security ?? ServicePipeSecurity()).GetSecurityDescriptorBinaryForm();
        nint handle;
        fixed (byte* bytes = descriptor)
        {
            // SECURITY_ATTRIBUTES { DWORD nLength; LPVOID lpSecurityDescriptor; BOOL bInheritHandle; } is three pointer-sized slots on
            // both Windows widths (x64: 4 + 4 padding, 8, 4 + 4 padding; x86: 4, 4, 4), little-endian. It lives on this frame for this
            // one call and points only at the managed descriptor pinned above: no type holds a native pointer and no native lifetime is
            // owned here (the pipe handle itself is a SafePipeHandle).
            var attributes = stackalloc nint[3];
            attributes[0] = 3 * sizeof(nint);
            attributes[1] = (nint)bytes;
            attributes[2] = 0;
            handle = CreateNamedPipe(
                @"\\.\pipe\" + name,
                PipeAccessDuplex | FileFlagOverlapped | (first ? FileFlagFirstPipeInstance : 0),
                PipeTypeByte | rejectFlag,
                PipeUnlimitedInstances,
                0,
                0,
                0,
                attributes);
        }

        if (handle == -1 || handle == 0)
        {
            var error = Marshal.GetLastPInvokeError();
            throw new IOException(
                first && error == ErrorAccessDenied
                    ? "The service pipe name is already in use; a service endpoint is never shared or replaced."
                    : "The service pipe could not be created.",
                new Win32Exception(error));
        }

        return Wrap(new SafePipeHandle(handle, ownsHandle: true));
    }

    [SuppressMessage("Reliability", "CA2000", Justification = "The pipe stream owns the handle once constructed; a failed construction disposes it here.")]
    private static NamedPipeServerStream Wrap(SafePipeHandle handle)
    {
        try
        {
            return new NamedPipeServerStream(PipeDirection.InOut, isAsync: true, isConnected: false, handle);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    /// <summary>The process id the OS recorded for the client end of a connected pipe instance, or null when it would not say.</summary>
    internal static int? ClientProcessId(NamedPipeServerStream pipe) =>
        GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var processId) && processId is > 0 and <= int.MaxValue ? (int)processId : null;

    /// <summary>Opens a process for limited queries; null with the Win32 error when it is gone or not openable.</summary>
    internal static SafeProcessHandle? OpenForQuery(int processId, out int error)
    {
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, (uint)processId);
        error = handle == 0 ? Marshal.GetLastPInvokeError() : 0;
        return handle == 0 ? null : new SafeProcessHandle(handle, ownsHandle: true);
    }

    /// <summary>True while the process has not exited. (A process that exited with code 259 reads as running: a documented OS limit.)</summary>
    internal static bool? IsRunning(SafeProcessHandle process) =>
        GetExitCodeProcess(process, out var code) ? code == StillActive : null;

    /// <summary>The process creation time (UTC), or null when the OS would not say.</summary>
    internal static DateTime? CreationTimeUtc(SafeProcessHandle process) =>
        GetProcessTimes(process, out var creation, out _, out _, out _) && creation > 0 ? DateTime.FromFileTimeUtc(creation) : null;

    /// <summary>The user SID of the process token, or null when the token could not be read.</summary>
    internal static string? TokenUser(SafeProcessHandle process)
    {
        if (!OpenProcessToken(process, TokenQuery, out var token) || token == 0)
        {
            return null;
        }

        using var safe = new SafeAccessTokenHandle(token);
        using var identity = new WindowsIdentity(safe.DangerousGetHandle());
        return identity.User?.Value;
    }

    /// <summary>The full Win32 path of the process image, or null when the OS would not say.</summary>
    internal static unsafe string? ImagePath(SafeProcessHandle process)
    {
        const int Capacity = 32_768;
        var buffer = new char[Capacity];
        fixed (char* characters = buffer)
        {
            var size = (uint)Capacity;
            return QueryFullProcessImageName(process, 0, characters, ref size) && size is > 0 and < Capacity
                ? new string(characters, 0, (int)size)
                : null;
        }
    }

    [LibraryImport("Kernel32.dll", EntryPoint = "CreateNamedPipeW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static unsafe partial nint CreateNamedPipe(
        string name,
        uint openMode,
        uint pipeMode,
        uint maxInstances,
        uint outBufferSize,
        uint inBufferSize,
        uint defaultTimeout,
        nint* securityAttributes);

    [LibraryImport("Kernel32.dll", EntryPoint = "GetNamedPipeClientProcessId", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);

    [LibraryImport("Kernel32.dll", EntryPoint = "OpenProcess", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial nint OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

    [LibraryImport("Kernel32.dll", EntryPoint = "GetExitCodeProcess", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetExitCodeProcess(SafeProcessHandle process, out uint exitCode);

    [LibraryImport("Kernel32.dll", EntryPoint = "GetProcessTimes", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetProcessTimes(SafeProcessHandle process, out long creationTime, out long exitTime, out long kernelTime, out long userTime);

    [LibraryImport("Kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, char* exeName, ref uint size);

    [LibraryImport("Advapi32.dll", EntryPoint = "OpenProcessToken", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenProcessToken(SafeProcessHandle process, uint desiredAccess, out nint token);
}
