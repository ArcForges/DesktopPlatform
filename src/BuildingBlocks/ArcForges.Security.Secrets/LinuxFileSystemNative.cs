// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Security.Secrets;

/// <summary>What <c>statx</c> reports about one path or open file, without following a final symbolic link.</summary>
internal readonly record struct LinuxFileStatus(LinuxFileKind Kind, uint Mode, uint OwnerId, ulong Inode, uint DeviceMajor,
    uint DeviceMinor, ulong Size)
{
    /// <summary>The permission bits (<c>0777</c>) only.</summary>
    public uint Permissions => Mode & 0x1FF;

    public bool SameFile(LinuxFileStatus other) =>
        Inode == other.Inode && DeviceMajor == other.DeviceMajor && DeviceMinor == other.DeviceMinor;
}

internal enum LinuxFileKind
{
    Other = 0,
    RegularFile = 1,
    Directory = 2,
    SymbolicLink = 3,
}

/// <summary>
/// The libc calls the owner-only file store needs and .NET does not expose: the file owner (<c>statx</c>, whose layout is the
/// same on every Linux architecture), the effective user and a directory <c>fsync</c> after an atomic rename.
/// </summary>
[SupportedOSPlatform("linux")]
internal static unsafe partial class LinuxFileSystemNative
{
    private const int AtFileDescriptorCurrentDirectory = -100;
    private const int AtSymlinkNoFollow = 0x100;
    private const int AtEmptyPath = 0x1000;
    private const uint StatxBasicStats = 0x7FF;
    private const uint StatxRequired = 0x1 | 0x2 | 0x8 | 0x100; // type, mode, uid, inode
    private const int StatxSize = 256;
    private const int OpenReadOnlyCloseOnExec = 0x80000; // O_RDONLY | O_CLOEXEC; the same value on every Linux architecture
    private const int NoSuchEntry = 2; // ENOENT
    private const int NotADirectory = 20; // ENOTDIR
    private const int InvalidArgument = 22; // EINVAL
    private const int NotSupported = 95; // EOPNOTSUPP

    /// <summary>The effective user ID of this process.</summary>
    public static uint EffectiveUserId => GetEffectiveUserId();

    /// <summary>Status of <paramref name="path"/> without following a final symbolic link, or <see langword="null"/> when it does not exist.</summary>
    public static LinuxFileStatus? TryGetStatus(string path)
    {
        byte[] encoded = Encode(path);
        Span<byte> buffer = stackalloc byte[StatxSize];
        int result;
        fixed (byte* pathPointer = encoded)
        fixed (byte* bufferPointer = buffer)
        {
            result = Statx(AtFileDescriptorCurrentDirectory, pathPointer, AtSymlinkNoFollow, StatxBasicStats, bufferPointer);
        }

        if (result != 0)
        {
            int error = Marshal.GetLastPInvokeError();
            if (error is NoSuchEntry or NotADirectory) return null;
            throw Failure(error, "Could not read the status of a secret-store path");
        }

        return Parse(buffer);
    }

    /// <summary>Status of an open file.</summary>
    public static LinuxFileStatus GetStatus(SafeFileHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        Span<byte> buffer = stackalloc byte[StatxSize];
        byte* empty = stackalloc byte[1];
        empty[0] = 0;
        bool added = false;
        int result;
        try
        {
            handle.DangerousAddRef(ref added);
            int descriptor = checked((int)handle.DangerousGetHandle());
            fixed (byte* bufferPointer = buffer)
            {
                result = Statx(descriptor, empty, AtEmptyPath, StatxBasicStats, bufferPointer);
            }
        }
        finally
        {
            if (added) handle.DangerousRelease();
        }

        if (result != 0) throw Failure(Marshal.GetLastPInvokeError(), "Could not read the status of an open secret file");
        return Parse(buffer);
    }

    /// <summary>Flushes a directory's entries, so a completed rename survives a crash.</summary>
    public static void SyncDirectory(string path)
    {
        byte[] encoded = Encode(path);
        int descriptor;
        fixed (byte* pathPointer = encoded)
        {
            descriptor = Open(pathPointer, OpenReadOnlyCloseOnExec);
        }

        if (descriptor < 0) throw Failure(Marshal.GetLastPInvokeError(), "Could not open the secret directory to flush it");
        try
        {
            if (Fsync(descriptor) != 0)
            {
                int error = Marshal.GetLastPInvokeError();
                // A file system without directory fsync (EINVAL/EOPNOTSUPP) has already ordered the rename as well as it can.
                if (error is not (InvalidArgument or NotSupported)) throw Failure(error, "Could not flush the secret directory");
            }
        }
        finally
        {
            _ = Close(descriptor);
        }
    }

    private static LinuxFileStatus Parse(ReadOnlySpan<byte> buffer)
    {
        uint mask = BinaryPrimitives.ReadUInt32LittleEndian(buffer);
        if (!BitConverter.IsLittleEndian || (mask & StatxRequired) != StatxRequired)
        {
            throw new IOException("The file system did not report the owner, type and mode of a secret-store path.");
        }

        uint owner = BinaryPrimitives.ReadUInt32LittleEndian(buffer[20..]);
        uint mode = BinaryPrimitives.ReadUInt16LittleEndian(buffer[28..]);
        ulong inode = BinaryPrimitives.ReadUInt64LittleEndian(buffer[32..]);
        ulong size = BinaryPrimitives.ReadUInt64LittleEndian(buffer[40..]);
        uint deviceMajor = BinaryPrimitives.ReadUInt32LittleEndian(buffer[136..]);
        uint deviceMinor = BinaryPrimitives.ReadUInt32LittleEndian(buffer[140..]);
        var kind = (mode & 0xF000) switch
        {
            0x8000 => LinuxFileKind.RegularFile,
            0x4000 => LinuxFileKind.Directory,
            0xA000 => LinuxFileKind.SymbolicLink,
            _ => LinuxFileKind.Other,
        };
        return new LinuxFileStatus(kind, mode, owner, inode, deviceMajor, deviceMinor, size);
    }

    private static byte[] Encode(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        if (path.Contains('\0', StringComparison.Ordinal)) throw new ArgumentException("A path cannot contain NUL.", nameof(path));
        byte[] encoded = new byte[Encoding.UTF8.GetByteCount(path) + 1];
        Encoding.UTF8.GetBytes(path, encoded);
        return encoded;
    }

    private static IOException Failure(int error, string message) =>
        new($"{message}: {Marshal.GetPInvokeErrorMessage(error)} (errno {error}).");

    [LibraryImport("libc", EntryPoint = "geteuid")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static partial uint GetEffectiveUserId();

    [LibraryImport("libc", EntryPoint = "statx", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static partial int Statx(int directory, byte* path, int flags, uint mask, byte* buffer);

    [LibraryImport("libc", EntryPoint = "open", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static partial int Open(byte* path, int flags);

    [LibraryImport("libc", EntryPoint = "fsync", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static partial int Fsync(int descriptor);

    [LibraryImport("libc", EntryPoint = "close", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static partial int Close(int descriptor);
}
