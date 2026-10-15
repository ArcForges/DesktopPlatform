// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace ArcForges.Security.Secrets.Tests;

/// <summary>
/// The owner-only file fallback on a real Linux file system (WSL2 Debian locally, the Linux runner in CI): modes, atomic replacement,
/// read and delete, refusal or repair of wrong permissions and ownership, and the protection it reports. No fakes.
/// </summary>
public sealed class OwnerOnlyFileSecretStoreTests : IDisposable
{
    private const string LinuxOnly = "The owner-only file fallback is the Linux backend (POSIX modes, statx owner checks).";
    private const UnixFileMode Mode0700 = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode Mode0600 = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode Mode0644 = Mode0600 | UnixFileMode.GroupRead | UnixFileMode.OtherRead;
    private const UnixFileMode Mode0755 = Mode0700 | UnixFileMode.GroupRead | UnixFileMode.GroupExecute
        | UnixFileMode.OtherRead | UnixFileMode.OtherExecute;

    private readonly string _root = Directory.CreateTempSubdirectory("afsf-").FullName;

    public static bool OnLinux => OperatingSystem.IsLinux();

    private string DataRoot => Path.Combine(_root, "data");

    public void Dispose()
    {
        if (OperatingSystem.IsLinux())
        {
            // Restore traversal so the temporary tree can always be removed.
            foreach (string directory in Directory.EnumerateDirectories(_root, "*", SearchOption.AllDirectories))
            {
                try
                {
                    File.SetUnixFileMode(directory, Mode0700);
                }
                catch (IOException)
                {
                }
            }
        }

        Directory.Delete(_root, recursive: true);
    }

    [Fact(Skip = LinuxOnly, SkipUnless = nameof(OnLinux))]
    [SupportedOSPlatform("linux")]
    public void WritesReadsReplacesAndDeletesOneOwnerOnlyFilePerSecret()
    {
        var store = new OwnerOnlyFileSecretStore(DataRoot);
        byte[] first = RandomNumberGenerator.GetBytes(32);
        byte[] second = RandomNumberGenerator.GetBytes(48);

        Assert.Null(store.Read("node-credential"));
        Assert.False(store.Delete("node-credential"));
        Assert.False(Directory.Exists(store.RunDirectory)); // a read or delete creates nothing

        store.Write("node-credential", first);
        Assert.Equal(first, store.Read("node-credential"));
        store.Write("node-credential", second);
        Assert.Equal(second, store.Read("node-credential"));
        store.Write("node-data-key", first);
        Assert.Equal(first, store.Read("node-data-key"));

        Assert.Equal(Path.Combine(DataRoot, "run", "secrets"), store.SecretDirectory);
        Assert.Equal(["node-credential", "node-data-key"],
            Directory.EnumerateFileSystemEntries(store.SecretDirectory).Select(Path.GetFileName).Order(StringComparer.Ordinal));
        Assert.True(store.Delete("node-credential"));
        Assert.Null(store.Read("node-credential"));
        Assert.False(store.Delete("node-credential"));
        Assert.Equal(first, store.Read("node-data-key"));
        Assert.Equal(SecretStoreIsolation.SameUserShared, store.Isolation);
        Assert.Equal(SecretStoreProtection.FileOwnerOnly, OwnerOnlyFileSecretStore.Protection);
    }

    [Fact(Skip = LinuxOnly, SkipUnless = nameof(OnLinux))]
    [SupportedOSPlatform("linux")]
    public void CreatesA0700DirectoryAnd0600FilesOwnedByTheCurrentUser()
    {
        var store = new OwnerOnlyFileSecretStore(DataRoot);
        store.Write("node-credential", RandomNumberGenerator.GetBytes(16));

        string file = Path.Combine(store.SecretDirectory, "node-credential");
        Assert.Equal(Mode0700, File.GetUnixFileMode(store.SecretDirectory));
        Assert.Equal(Mode0700, File.GetUnixFileMode(store.RunDirectory));
        Assert.Equal(Mode0600, File.GetUnixFileMode(file));
        uint user = LinuxFileSystemNative.EffectiveUserId;
        Assert.Equal(user, LinuxFileSystemNative.TryGetStatus(store.SecretDirectory)!.Value.OwnerId);
        var status = LinuxFileSystemNative.TryGetStatus(file)!.Value;
        Assert.Equal(user, status.OwnerId);
        Assert.Equal(LinuxFileKind.RegularFile, status.Kind);
        Assert.Equal(0, store.PermissionRepairs);
    }

    [Fact(Skip = LinuxOnly, SkipUnless = nameof(OnLinux))]
    [SupportedOSPlatform("linux")]
    public void ReplacementIsAnAtomicRenameThatLeavesNoTemporaryFile()
    {
        var store = new OwnerOnlyFileSecretStore(DataRoot);
        byte[] first = Encoding.ASCII.GetBytes(new string('a', 2048));
        byte[] second = Encoding.ASCII.GetBytes(new string('b', 1024));
        store.Write("node-credential", first);
        string file = Path.Combine(store.SecretDirectory, "node-credential");
        var before = LinuxFileSystemNative.TryGetStatus(file)!.Value;

        // A reader that opened the previous file keeps the complete previous value; the name now holds the complete new one.
        using (var previous = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        {
            store.Write("node-credential", second);
            using var copy = new MemoryStream();
            previous.CopyTo(copy);
            Assert.Equal(first, copy.ToArray());
        }

        var after = LinuxFileSystemNative.TryGetStatus(file)!.Value;
        Assert.False(after.SameFile(before)); // a new inode was renamed over the name, the old file was never rewritten in place
        Assert.Equal(second, store.Read("node-credential"));
        Assert.Equal(Mode0600, File.GetUnixFileMode(file));
        Assert.Equal(["node-credential"], Directory.EnumerateFileSystemEntries(store.SecretDirectory).Select(Path.GetFileName));
    }

    [Fact(Skip = LinuxOnly, SkipUnless = nameof(OnLinux))]
    [SupportedOSPlatform("linux")]
    public void ALeftoverTemporaryFromAnInterruptedWriteIsNeverReadAndIsRemovedOnTheNextWrite()
    {
        var store = new OwnerOnlyFileSecretStore(DataRoot);
        store.Write("node-credential", "current"u8);
        string stale = Path.Combine(store.SecretDirectory, ".node-credential.0123456789abcdef.tmp");
        string unrelated = Path.Combine(store.SecretDirectory, ".node-credential.not-ours.tmp");
        File.WriteAllBytes(stale, "interrupted"u8.ToArray());
        File.WriteAllBytes(unrelated, "other"u8.ToArray());

        Assert.Equal("current"u8.ToArray(), store.Read("node-credential"));
        store.Write("node-credential", "next"u8);

        Assert.False(File.Exists(stale));
        Assert.True(File.Exists(unrelated)); // only the exact temporary shape is removed
        Assert.Equal("next"u8.ToArray(), store.Read("node-credential"));
    }

    [Fact(Skip = LinuxOnly, SkipUnless = nameof(OnLinux))]
    [SupportedOSPlatform("linux")]
    public void AWiderSecretDirectoryIsRepairedTo0700()
    {
        var store = new OwnerOnlyFileSecretStore(DataRoot);
        store.Write("node-credential", "value"u8);
        File.SetUnixFileMode(store.SecretDirectory, Mode0755);

        Assert.Equal("value"u8.ToArray(), store.Read("node-credential"));

        Assert.Equal(Mode0700, File.GetUnixFileMode(store.SecretDirectory));
        Assert.Equal(1, store.PermissionRepairs);
    }

    [Fact(Skip = LinuxOnly, SkipUnless = nameof(OnLinux))]
    [SupportedOSPlatform("linux")]
    public void ASecretFileOtherUsersCouldReadIsRefusedUntilItIsStoredAgainOrDeleted()
    {
        var store = new OwnerOnlyFileSecretStore(DataRoot);
        store.Write("node-credential", "exposed"u8);
        string file = Path.Combine(store.SecretDirectory, "node-credential");
        File.SetUnixFileMode(file, Mode0644);

        var refused = Assert.Throws<UnauthorizedAccessException>(() => store.Read("node-credential"));
        Assert.Contains("accessible to other users", refused.Message, StringComparison.Ordinal);
        Assert.Equal(Mode0644, File.GetUnixFileMode(file)); // a file is never silently trusted again by widening repairs

        store.Write("node-credential", "rotated"u8);
        Assert.Equal(Mode0600, File.GetUnixFileMode(file));
        Assert.Equal("rotated"u8.ToArray(), store.Read("node-credential"));

        File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
        Assert.Throws<UnauthorizedAccessException>(() => store.Read("node-credential"));
        Assert.True(store.Delete("node-credential"));
        Assert.False(File.Exists(file));
    }

    [Fact(Skip = LinuxOnly, SkipUnless = nameof(OnLinux))]
    [SupportedOSPlatform("linux")]
    public void SymbolicLinksAreRefusedForTheSecretFileAndTheSecretDirectory()
    {
        var store = new OwnerOnlyFileSecretStore(DataRoot);
        store.Write("node-data-key", "value"u8);
        string target = Path.Combine(_root, "elsewhere");
        File.WriteAllBytes(target, "planted"u8.ToArray());
        File.SetUnixFileMode(target, Mode0600);
        File.CreateSymbolicLink(Path.Combine(store.SecretDirectory, "node-credential"), target);

        Assert.Throws<UnauthorizedAccessException>(() => store.Read("node-credential"));
        Assert.True(store.Delete("node-credential")); // removes the link, never its target
        Assert.True(File.Exists(target));

        var linked = new OwnerOnlyFileSecretStore(Path.Combine(_root, "linked"));
        Directory.CreateDirectory(Path.Combine(_root, "linked", "run"), Mode0700);
        string realSecrets = Path.Combine(_root, "real-secrets");
        Directory.CreateDirectory(realSecrets, Mode0700);
        Directory.CreateSymbolicLink(linked.SecretDirectory, realSecrets);
        Assert.Throws<UnauthorizedAccessException>(() => linked.Write("node-credential", "value"u8));
        Assert.Throws<UnauthorizedAccessException>(() => linked.Read("node-credential"));
        Assert.Empty(Directory.EnumerateFileSystemEntries(realSecrets));
    }

    [Fact(Skip = LinuxOnly, SkipUnless = nameof(OnLinux))]
    [SupportedOSPlatform("linux")]
    public void ADataRootThatIsALinkOrWritableByOthersIsRefusedAndAMissingOneIsCreatedOwnerOnly()
    {
        // Missing: created 0700 with run/ and run/secrets/ on the first write; a read or delete creates nothing.
        var created = new OwnerOnlyFileSecretStore(Path.Combine(_root, "fresh", "data"));
        Assert.Null(created.Read("node-credential"));
        Assert.False(Directory.Exists(created.DataRoot));
        created.Write("node-credential", "value"u8);
        Assert.Equal(Mode0700, File.GetUnixFileMode(created.DataRoot));

        // A symbolic link as the data root is refused, even when it points at an owner-only directory of the user.
        string real = Path.Combine(_root, "real-root");
        Directory.CreateDirectory(real, Mode0700);
        string link = Path.Combine(_root, "linked-root");
        Directory.CreateSymbolicLink(link, real);
        var linked = new OwnerOnlyFileSecretStore(link);
        Assert.Contains("data root", Assert.Throws<UnauthorizedAccessException>(() => linked.Write("node-credential", "value"u8)).Message,
            StringComparison.Ordinal);
        Assert.Throws<UnauthorizedAccessException>(() => linked.Read("node-credential"));
        Assert.Empty(Directory.EnumerateFileSystemEntries(real));

        // A data root other users can write is refused; one they can only read and traverse is accepted.
        var store = new OwnerOnlyFileSecretStore(DataRoot);
        Directory.CreateDirectory(DataRoot, Mode0700);
        File.SetUnixFileMode(DataRoot, Mode0755 | UnixFileMode.GroupWrite);
        Assert.Throws<UnauthorizedAccessException>(() => store.Write("node-credential", "value"u8));
        File.SetUnixFileMode(DataRoot, Mode0755 | UnixFileMode.OtherWrite);
        Assert.Throws<UnauthorizedAccessException>(() => store.Write("node-credential", "value"u8));
        Assert.False(Directory.Exists(store.RunDirectory));
        File.SetUnixFileMode(DataRoot, Mode0755);
        store.Write("node-credential", "value"u8);
        Assert.Equal("value"u8.ToArray(), store.Read("node-credential"));
    }

    [Fact(Skip = LinuxOnly, SkipUnless = nameof(OnLinux))]
    [SupportedOSPlatform("linux")]
    public void ARunDirectoryOfAnotherUserOrWritableByOthersIsRefused()
    {
        // Data root "/" (owned by root, so /run is too): refused before anything is created (never run as root).
        Assert.SkipWhen(LinuxFileSystemNative.EffectiveUserId == 0, "Running as root: /run would belong to the current user.");
        var system = new OwnerOnlyFileSecretStore("/");
        var foreign = Assert.Throws<UnauthorizedAccessException>(() => system.Write("node-credential", "value"u8));
        Assert.Contains("data root", foreign.Message, StringComparison.Ordinal);
        Assert.Throws<UnauthorizedAccessException>(() => system.Read("node-credential"));
        Assert.NotEqual(LinuxFileSystemNative.EffectiveUserId, LinuxFileSystemNative.TryGetStatus("/run/secrets")?.OwnerId);

        var store = new OwnerOnlyFileSecretStore(DataRoot);
        Directory.CreateDirectory(store.RunDirectory, Mode0700);
        File.SetUnixFileMode(store.RunDirectory, Mode0700 | UnixFileMode.GroupWrite | UnixFileMode.GroupRead | UnixFileMode.GroupExecute
            | UnixFileMode.OtherWrite | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
        Assert.Throws<UnauthorizedAccessException>(() => store.Write("node-credential", "value"u8));
        Assert.False(Directory.Exists(store.SecretDirectory));

        File.SetUnixFileMode(store.RunDirectory, Mode0755); // readable by others is fine; only writable is refused
        store.Write("node-credential", "value"u8);
        Assert.Equal("value"u8.ToArray(), store.Read("node-credential"));
    }

    [Fact(Skip = LinuxOnly, SkipUnless = nameof(OnLinux))]
    [SupportedOSPlatform("linux")]
    public void TheFileDecisionRefusesAnotherOwnerAnyGroupOrOtherBitAndNonRegularFiles()
    {
        // The same decision the store applies to the statx result of every secret file (before and after opening it). A file of
        // another user cannot be created without privileges, so that branch is exercised here on the decision itself.
        const uint user = 1000;
        var own = new LinuxFileStatus(LinuxFileKind.RegularFile, 0x8180, user, 1, 8, 1, 5); // -rw------- of the user
        OwnerOnlyFileSecretStore.RequireOwnerOnlyFile(own, user);
        OwnerOnlyFileSecretStore.RequireOwnerOnlyFile(own with { Mode = 0x8100 }, user); // 0400 stays owner-only
        Assert.Contains("another user", Assert.Throws<UnauthorizedAccessException>(() =>
            OwnerOnlyFileSecretStore.RequireOwnerOnlyFile(own with { OwnerId = 0 }, user)).Message, StringComparison.Ordinal);
        foreach (uint mode in new uint[] { 0x81A0, 0x8184, 0x8182, 0x8188, 0x8181, 0x81B6 }) // 0640, 0604, 0602, 0610, 0601, 0666
        {
            Assert.Throws<UnauthorizedAccessException>(() => OwnerOnlyFileSecretStore.RequireOwnerOnlyFile(own with { Mode = mode }, user));
        }

        Assert.Throws<UnauthorizedAccessException>(() =>
            OwnerOnlyFileSecretStore.RequireOwnerOnlyFile(own with { Kind = LinuxFileKind.SymbolicLink, Mode = 0xA1FF }, user));
        Assert.Throws<UnauthorizedAccessException>(() =>
            OwnerOnlyFileSecretStore.RequireOwnerOnlyFile(own with { Kind = LinuxFileKind.Directory, Mode = 0x41C0 }, user));
        Assert.True(own.SameFile(own with { Mode = 0x81A4 }));
        Assert.False(own.SameFile(own with { Inode = 2 }));
        Assert.False(own.SameFile(own with { DeviceMinor = 2 }));
    }

    [Theory]
    [InlineData("")]
    [InlineData(".hidden")]
    [InlineData("..")]
    [InlineData("../node-credential")]
    [InlineData("run/node-credential")]
    [InlineData("-leading-dash")]
    [InlineData("space key")]
    [InlineData("nul\0key")]
    [InlineData("ключ")]
    public void KeysThatAreNotOneSafeFileNameAreRejectedByEveryBackend(string key)
    {
        Assert.ThrowsAny<ArgumentException>(() => SecretStoreKey.Validate(key, "key"));
        Assert.ThrowsAny<ArgumentException>(() => SecretStoreKey.Validate(new string('a', SecretStoreKey.MaximumLength + 1), "key"));
        SecretStoreKey.Validate(new string('a', SecretStoreKey.MaximumLength), "key");
        SecretStoreKey.Validate("node-credential", "key");
        SecretStoreKey.Validate("ArcForges.Secrets.v1." + new string('A', 64), "key"); // the broker's canonical opaque target
        Assert.Throws<ArgumentOutOfRangeException>(() => SecretStoreKey.ValidateValue([], "secret"));
        Assert.Throws<ArgumentOutOfRangeException>(() => SecretStoreKey.ValidateValue(new byte[SecretBroker.MaximumSecretBytes + 1], "secret"));
        SecretStoreKey.ValidateValue(new byte[SecretBroker.MaximumSecretBytes], "secret");
    }

    [Fact(Skip = LinuxOnly, SkipUnless = nameof(OnLinux))]
    [SupportedOSPlatform("linux")]
    public void TheFallbackRejectsARelativeDataRootAndOutOfBoundValues()
    {
        Assert.Throws<ArgumentException>(() => new OwnerOnlyFileSecretStore("relative/data"));
        var store = new OwnerOnlyFileSecretStore(DataRoot);
        Assert.Throws<ArgumentOutOfRangeException>(() => store.Write("node-credential", ReadOnlySpan<byte>.Empty));
        Assert.Throws<ArgumentOutOfRangeException>(() => store.Write("node-credential", new byte[SecretBroker.MaximumSecretBytes + 1]));
        Assert.Throws<ArgumentException>(() => store.Write("../escape", "value"u8));
        Assert.False(Directory.Exists(store.RunDirectory));
        store.Write("node-credential", new byte[SecretBroker.MaximumSecretBytes]);
        Assert.Equal(SecretBroker.MaximumSecretBytes, store.Read("node-credential")!.Length);
    }
}
