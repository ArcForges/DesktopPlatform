// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Security.Secrets;
using Xunit;

namespace ArcForges.Tests.OsSecretStoreTests;

/// <summary>
/// The Windows Credential Manager adapter against the real store (the OS secret-store tier; formerly the local opt-in
/// ARCFORGES_LOCAL_OS_SECRET_STORE tests of ArcForges.Security.Secrets.Tests). Minimal and sequential: each test creates at most one
/// uniquely named entry through the tier fixture, performs only the operations its contract needs, deletes it by exact name and
/// verifies that it is absent. The read-backs are test verification, not production behaviour.
/// </summary>
[Collection(OsSecretStoreTierDefinition.Name)]
[Trait("env", "os-secret-store")]
[SupportedOSPlatform("windows")]
public sealed class WindowsCredentialManagerTierTests(OsSecretStoreTier tier)
{
    [Fact(Skip = OsSecretStoreTier.WindowsTierReason, SkipUnless = nameof(OsSecretStoreTier.WindowsTier),
        SkipType = typeof(OsSecretStoreTier))]
    public void AnEntryIsWrittenOverwrittenReadAndDeletedAndThenAbsent()
    {
        var store = new WindowsCredentialManagerSecretStore();
        string name = tier.NewEntry(store);
        byte[] first = RandomNumberGenerator.GetBytes(32);
        byte[] second = RandomNumberGenerator.GetBytes(48);
        try
        {
            tier.Call("write", () => store.Write(name, first));
            Assert.Equal(first, tier.Call("read", () => store.Read(name)));
            tier.Call("overwrite", () => store.Write(name, second));
            Assert.Equal(second, tier.Call("read", () => store.Read(name)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(first);
            CryptographicOperations.ZeroMemory(second);
            tier.Remove(name);
        }
    }

    [Fact(Skip = OsSecretStoreTier.WindowsTierReason, SkipUnless = nameof(OsSecretStoreTier.WindowsTier),
        SkipType = typeof(OsSecretStoreTier))]
    public void AMissingEntryReadsAsAbsentAndIsNotDeleted()
    {
        var store = new WindowsCredentialManagerSecretStore();
        string name = tier.NewEntry(store); // listed although never created, so even this name is accounted for
        Assert.False(tier.Call("delete missing", () => store.Delete(name)));
        tier.VerifyAbsent(name, store);
    }

    [Fact(Skip = OsSecretStoreTier.WindowsTierReason, SkipUnless = nameof(OsSecretStoreTier.WindowsTier),
        SkipType = typeof(OsSecretStoreTier))]
    public void AnEntryIsVisibleToASameUserSiblingProcessSoItIsNotAnOsIsolationBoundary()
    {
        var store = new WindowsCredentialManagerSecretStore();
        Assert.Equal(SecretStoreIsolation.SameUserShared, store.Isolation);
        string name = tier.NewEntry(store);
        byte[] value = RandomNumberGenerator.GetBytes(32);
        try
        {
            tier.Call("write", () => store.Write(name, value));
            // A different process of the same Windows user, with no ArcForges code, addresses the entry by name (one listing of that
            // exact name; it reads no value and changes nothing). It runs alone, inside the tier's call limits.
            string output = tier.Call("cmdkey /list", () => ListWithCmdkey(name));
            Assert.Contains(name, output, StringComparison.Ordinal);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(value);
            tier.Remove(name);
        }
    }

    [Fact(Skip = OsSecretStoreTier.WindowsTierReason, SkipUnless = nameof(OsSecretStoreTier.WindowsTier),
        SkipType = typeof(OsSecretStoreTier))]
    public void TheWindowsSelectionIsCredentialManagerReportedAsTheSharedOsStore()
    {
        // Selection only constructs the adapter: no store call, nothing written.
        string dataRoot = Path.Combine(Path.GetTempPath(), "arcforges-unused-data-root");
        var selection = OsSecretStore.SelectForCurrentPlatform(dataRoot);
        var store = Assert.IsType<WindowsCredentialManagerSecretStore>(selection.Store);
        Assert.IsType<WindowsCredentialManagerSecretStore>(OsSecretStore.CreateForCurrentPlatform());
        Assert.Equal(SecretStoreBackend.WindowsCredentialManager, selection.Backend);
        Assert.Equal(SecretStoreProtection.OsSecretStore, selection.Protection);
        Assert.True(selection.CredentialInOsStore);
        Assert.Null(selection.FallbackReason);
        Assert.Equal(SecretStoreIsolation.SameUserShared, store.Isolation);
        var installation = new SecretInstallationBinding(SecretApplicationDimension.ArcScope, new DeviceId(Guid.NewGuid()),
            new InstallationId(Guid.NewGuid()));
        Assert.Throws<NotSupportedException>(() => new SecretBroker(installation, new NoContext(), store, new NoConnector(),
            SecretIsolationPolicy.RequireOsEnforcedPerApplication));
        Assert.False(Directory.Exists(dataRoot));
    }

    private static string ListWithCmdkey(string name)
    {
        string cmdkey = Path.Combine(Environment.SystemDirectory, "cmdkey.exe");
        using var sibling = Process.Start(new ProcessStartInfo(cmdkey)
        {
            ArgumentList = { "/list:" + name },
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        }) ?? throw new InvalidOperationException("cmdkey did not start.");
        var output = sibling.StandardOutput.ReadToEndAsync();
        if (!sibling.WaitForExit(OsSecretStoreTier.CallTimeout))
        {
            sibling.Kill(entireProcessTree: true);
            throw new TimeoutException("cmdkey did not finish within the tier's call timeout.");
        }

        return output.GetAwaiter().GetResult();
    }

    private sealed class NoContext : ISecretHostContextProvider
    {
        public SecretHostContext GetCurrent() => throw new InvalidOperationException("No host context in this test.");
    }

    private sealed class NoConnector : IConnectorSecretOperationExecutor
    {
        public void Execute(string connectorDefinitionId, ReadOnlySpan<byte> secret) =>
            throw new InvalidOperationException("No connector operation in this test.");
    }
}
