// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace ArcForges.Security.Secrets;

/// <summary>
/// The Linux fallback when no Secret Service is available: one secret per file under <c>&lt;data root&gt;/run/secrets/</c>,
/// mode 0600 in a 0700 directory, each replaced atomically by <c>rename</c>. It reports
/// <see cref="SecretStoreProtection.FileOwnerOnly"/>, which the node shows as weaker storage (R-AUTH-003).
/// </summary>
/// <remarks>
/// <para>Before each operation the store checks what it relies on and fails closed otherwise:</para>
/// <list type="bullet">
/// <item><c>run/</c> is a real directory (not a symbolic link) of the current user that no other user can write;</item>
/// <item><c>run/secrets/</c> is a real directory of the current user; a mode other than 0700 is repaired to 0700, because
/// tightening it is safe and the files inside are checked one by one;</item>
/// <item>a secret file is a regular file (not a link) of the current user without any group or other permission; anything else is
/// refused on read, because its contents may have been exposed or planted. Writing the key replaces it and deleting it removes it.</item>
/// </list>
/// <para>The data root itself belongs to the node (its own directory, architecture 06 §1).</para>
/// </remarks>
[SupportedOSPlatform("linux")]
internal sealed class OwnerOnlyFileSecretStore : ISecretBackingStore
{
    internal const UnixFileMode DirectoryMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    internal const UnixFileMode SecretFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const uint GroupOrOtherWrite = 0x12; // 0022
    private const uint GroupOrOtherAny = 0x3F; // 0077
    private const string TemporarySuffix = ".tmp";
    private const int TemporaryRandomHexLength = 16;
    private static readonly Lock Gate = new();
    private static readonly SearchValues<char> LowerHex = SearchValues.Create("0123456789abcdef");
    private int _permissionRepairs;

    public OwnerOnlyFileSecretStore(string dataRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataRoot);
        if (!Path.IsPathFullyQualified(dataRoot) || dataRoot.Contains('\0', StringComparison.Ordinal))
        {
            throw new ArgumentException("The node data root must be an absolute path.", nameof(dataRoot));
        }

        DataRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(dataRoot));
        RunDirectory = Path.Combine(DataRoot, "run");
        SecretDirectory = Path.Combine(RunDirectory, "secrets");
    }

    public SecretStoreIsolation Isolation => SecretStoreIsolation.SameUserShared;

    public static SecretStoreProtection Protection => SecretStoreProtection.FileOwnerOnly;

    internal string DataRoot { get; }
    internal string RunDirectory { get; }
    internal string SecretDirectory { get; }

    /// <summary>How often this instance tightened the secret directory back to 0700.</summary>
    internal int PermissionRepairs => Volatile.Read(ref _permissionRepairs);

    public void Write(string opaqueTarget, ReadOnlySpan<byte> secret)
    {
        SecretStoreKey.Validate(opaqueTarget, nameof(opaqueTarget));
        SecretStoreKey.ValidateValue(secret, nameof(secret));
        lock (Gate)
        {
            PrepareDirectories(create: true);
            string target = Path.Combine(SecretDirectory, opaqueTarget);
            string temporary = Path.Combine(SecretDirectory,
                "." + opaqueTarget + "." + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(TemporaryRandomHexLength / 2)) + TemporarySuffix);
            bool renamed = false;
            try
            {
                var options = new FileStreamOptions
                {
                    Mode = FileMode.CreateNew,
                    Access = FileAccess.Write,
                    Share = FileShare.None,
                    UnixCreateMode = SecretFileMode,
                };
                using (var stream = new FileStream(temporary, options))
                {
                    // Exactly 0600 whatever the umask, before any byte is written.
                    File.SetUnixFileMode(stream.SafeFileHandle, SecretFileMode);
                    stream.Write(secret);
                    stream.Flush(flushToDisk: true);
                }

                // rename(2): a reader sees the previous complete file or the new complete file, never a partial one.
                File.Move(temporary, target, overwrite: true);
                renamed = true;
                LinuxFileSystemNative.SyncDirectory(SecretDirectory);
            }
            finally
            {
                if (!renamed) TryDelete(temporary);
            }

            RemoveTemporaries(opaqueTarget);
        }
    }

    public byte[]? Read(string opaqueTarget)
    {
        SecretStoreKey.Validate(opaqueTarget, nameof(opaqueTarget));
        lock (Gate)
        {
            if (!PrepareDirectories(create: false)) return null;
            string path = Path.Combine(SecretDirectory, opaqueTarget);
            if (LinuxFileSystemNative.TryGetStatus(path) is not { } before) return null;
            RequireOwnerOnlyFile(before, LinuxFileSystemNative.EffectiveUserId);
            using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var opened = LinuxFileSystemNative.GetStatus(handle);
            if (!opened.SameFile(before))
            {
                throw new IOException("A secret file was replaced while it was being opened; read it again.");
            }

            RequireOwnerOnlyFile(opened, LinuxFileSystemNative.EffectiveUserId);
            if (opened.Size is 0 or > SecretBroker.MaximumSecretBytes)
            {
                throw new InvalidDataException("A secret file is empty or larger than the secret-store bound.");
            }

            byte[] secret = new byte[(int)opened.Size];
            int total = 0;
            while (total < secret.Length)
            {
                int read = RandomAccess.Read(handle, secret.AsSpan(total), total);
                if (read == 0)
                {
                    CryptographicOperations.ZeroMemory(secret);
                    throw new InvalidDataException("A secret file was truncated while it was read.");
                }

                total += read;
            }

            return secret;
        }
    }

    public bool Delete(string opaqueTarget)
    {
        SecretStoreKey.Validate(opaqueTarget, nameof(opaqueTarget));
        lock (Gate)
        {
            if (!PrepareDirectories(create: false)) return false;
            string path = Path.Combine(SecretDirectory, opaqueTarget);
            if (LinuxFileSystemNative.TryGetStatus(path) is not { } status) return false;
            if (status.Kind == LinuxFileKind.Directory)
            {
                throw new IOException("A directory occupies a secret file name; it is not removed.");
            }

            // Unlinking a name in our own 0700 directory is safe whatever it points to: a link is removed, not followed.
            File.Delete(path);
            LinuxFileSystemNative.SyncDirectory(SecretDirectory);
            RemoveTemporaries(opaqueTarget);
            return true;
        }
    }

    /// <summary>Checks (and creates when asked) <c>run</c> and <c>run/secrets</c>; returns whether the secret directory exists.</summary>
    private bool PrepareDirectories(bool create)
    {
        uint user = LinuxFileSystemNative.EffectiveUserId;
        var run = LinuxFileSystemNative.TryGetStatus(RunDirectory);
        if (run is null)
        {
            if (!create) return false;
            Directory.CreateDirectory(RunDirectory, DirectoryMode);
            run = LinuxFileSystemNative.TryGetStatus(RunDirectory);
        }

        if (run is not { Kind: LinuxFileKind.Directory } runStatus || runStatus.OwnerId != user
            || (runStatus.Permissions & GroupOrOtherWrite) != 0)
        {
            throw new UnauthorizedAccessException(
                "The node run directory must be a directory of the current user that other users cannot write; the secret fallback refuses it.");
        }

        var secrets = LinuxFileSystemNative.TryGetStatus(SecretDirectory);
        if (secrets is null)
        {
            if (!create) return false;
            Directory.CreateDirectory(SecretDirectory, DirectoryMode);
            secrets = LinuxFileSystemNative.TryGetStatus(SecretDirectory);
        }

        if (secrets is not { Kind: LinuxFileKind.Directory } secretStatus || secretStatus.OwnerId != user)
        {
            throw new UnauthorizedAccessException(
                "The secret directory must be a real directory of the current user; the secret fallback refuses it.");
        }

        if (secretStatus.Permissions != (uint)DirectoryMode)
        {
            File.SetUnixFileMode(SecretDirectory, DirectoryMode);
            Interlocked.Increment(ref _permissionRepairs);
            if (LinuxFileSystemNative.TryGetStatus(SecretDirectory) is not { } repaired || !repaired.SameFile(secretStatus)
                || repaired.Permissions != (uint)DirectoryMode)
            {
                throw new UnauthorizedAccessException("The secret directory could not be restricted to its owner.");
            }
        }

        return true;
    }

    /// <summary>The decision applied to every secret file status: a regular file of <paramref name="user"/> without group or other bits.</summary>
    internal static void RequireOwnerOnlyFile(LinuxFileStatus status, uint user)
    {
        if (status.Kind != LinuxFileKind.RegularFile)
        {
            throw new UnauthorizedAccessException("A secret entry is not a regular file (for example a symbolic link); it is refused.");
        }

        if (status.OwnerId != user)
        {
            throw new UnauthorizedAccessException("A secret file belongs to another user; it is refused.");
        }

        if ((status.Permissions & GroupOrOtherAny) != 0)
        {
            throw new UnauthorizedAccessException(
                "A secret file is accessible to other users, so its value may be exposed; it is refused. Store the secret again or delete it.");
        }
    }

    // A crash between create and rename leaves ".<key>.<16 hex>.tmp"; only that exact shape is ever removed.
    private void RemoveTemporaries(string key)
    {
        string prefix = "." + key + ".";
        foreach (string path in Directory.EnumerateFiles(SecretDirectory, "." + key + ".*" + TemporarySuffix))
        {
            string name = Path.GetFileName(path);
            if (name.Length != prefix.Length + TemporaryRandomHexLength + TemporarySuffix.Length
                || !name.StartsWith(prefix, StringComparison.Ordinal) || !name.EndsWith(TemporarySuffix, StringComparison.Ordinal)
                || name.AsSpan(prefix.Length, TemporaryRandomHexLength).ContainsAnyExcept(LowerHex))
            {
                continue;
            }

            TryDelete(path);
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
