// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using Xunit;

namespace ArcForges.Security.Secrets.Tests;

/// <summary>
/// The negative tests of the OS secret-store test guard (ArcForges-Design 16-testing-strategy section 1, guard item 4): in this
/// routine test process, which sets the tripwire switch and has no opt-in, every path to a real OS secret store of the user is
/// refused with the guard's error before any OS call. Each refused call is chosen so that it makes no OS call even if the tripwire
/// were missing: an adapter constructor, an operation with a non-canonical target (refused by validation before P/Invoke), a
/// Windows selection (which only constructs), or a Linux selection without any session bus. Without the tripwire these tests fail
/// with a different outcome, never by reaching a store.
/// </summary>
public sealed class OsSecretStoreGuardTests : IDisposable
{
    private const string WindowsOnly = "The Windows Credential Manager adapter exists only on Windows.";
    private const string LinuxOnly = "The Secret Service adapter exists only on Linux.";
    private const string NotCanonical = "not-a-canonical-target";

    private readonly string _root = Directory.CreateTempSubdirectory("afguard-").FullName;

    public OsSecretStoreGuardTests()
    {
        // The precondition of every test here: this routine process must not carry the tier's opt-in (the test scripts remove it).
        // It fails before any adapter is touched, so a stray value can never turn these tests into real-store calls.
        Assert.Null(Environment.GetEnvironmentVariable(OsSecretStoreGuard.OptInVariable));
    }

    public static bool OnWindows => OperatingSystem.IsWindows();

    public static bool OnLinux => OperatingSystem.IsLinux();

    private string DataRoot => Path.Combine(_root, "data");

    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact]
    public void ThisTestProcessSetsTheTripwireSwitchFromItsRuntimeConfiguration()
    {
        Assert.True(AppContext.TryGetSwitch(OsSecretStoreGuard.DenyOsStoresSwitch, out bool deny));
        Assert.True(deny);
        Assert.True(OsSecretStoreGuard.IsDenied);
        var refusal = Assert.Throws<OsSecretStoreDeniedException>(() => OsSecretStoreGuard.ThrowIfDenied("a CNG user key store"));
        Assert.Contains("a CNG user key store", refusal.Message, StringComparison.Ordinal);
        Assert.Contains(OsSecretStoreGuard.OptInVariable + "=1", refusal.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(true, null, true)]
    [InlineData(true, "", true)]
    [InlineData(true, "0", true)]
    [InlineData(true, "true", true)]
    [InlineData(true, " 1", true)]
    [InlineData(true, "1", false)]
    [InlineData(false, null, false)]
    [InlineData(null, null, false)]
    public void OnlyTheExactOptInLiftsTheSwitchAndProductionWithoutTheSwitchIsUnchanged(bool? denySwitch, string? optIn, bool denied) =>
        Assert.Equal(denied, OsSecretStoreGuard.IsDeniedBy(denySwitch, optIn));

    [Fact(Skip = WindowsOnly, SkipUnless = nameof(OnWindows))]
    [SupportedOSPlatform("windows")]
    public void TheCredentialManagerAdapterIsRefusedAtConstructionAndAtEveryOperation()
    {
        // Construction makes no OS call, so without the tripwire this would only fail the assertion.
        Assert.Throws<OsSecretStoreDeniedException>(() => new WindowsCredentialManagerSecretStore());

        // An instance obtained without its constructor still refuses each operation before target validation. The target is not
        // canonical, so without the tripwire validation would refuse it before any P/Invoke and the test would fail on the type.
        var store = (WindowsCredentialManagerSecretStore)RuntimeHelpers.GetUninitializedObject(typeof(WindowsCredentialManagerSecretStore));
        Assert.Throws<OsSecretStoreDeniedException>(() => store.Write(NotCanonical, "value"u8));
        Assert.Throws<OsSecretStoreDeniedException>(() => store.Read(NotCanonical));
        Assert.Throws<OsSecretStoreDeniedException>(() => store.Delete(NotCanonical));
    }

    [Fact(Skip = WindowsOnly, SkipUnless = nameof(OnWindows))]
    public void TheWindowsSelectionPropagatesTheRefusalAndNeverFallsBack()
    {
        // Both entry points only construct the adapter on Windows: without the tripwire they would return it, not reach the store.
        Assert.Throws<OsSecretStoreDeniedException>(() => OsSecretStore.SelectForCurrentPlatform(DataRoot));
        Assert.Throws<OsSecretStoreDeniedException>(() => OsSecretStore.CreateForCurrentPlatform());
        Assert.False(Directory.Exists(DataRoot));
    }

    [Fact(Skip = LinuxOnly, SkipUnless = nameof(OnLinux))]
    [SupportedOSPlatform("linux")]
    public void TheLinuxSelectionWithoutAnExplicitBusIsRefusedAndNeverFallsBackToTheFileStore()
    {
        // No explicit address means the user's session bus. With no session bus at all (null), an unguarded selection makes no bus
        // call and would choose the file fallback, so this test can only fail by assertion, never by reaching the user's bus.
        Assert.Throws<OsSecretStoreDeniedException>(() =>
            OsSecretStore.SelectLinux(DataRoot, new SecretServiceOptions(), sessionBusAddress: null));
        Assert.Throws<OsSecretStoreDeniedException>(() =>
            SecretServiceSecretStore.TryOpen(address: null, new SecretServiceOptions(), out _, out _));
        Assert.False(Directory.Exists(Path.Combine(DataRoot, "run")));
    }

    [Theory]
    // The user's session bus: the environment's address, the standard per-user socket and $XDG_RUNTIME_DIR/bus.
    [InlineData("unix:path=/run/user/1000/bus,guid=0123", "unix:path=/run/user/1000/bus,guid=0123", true)]
    [InlineData("unix:path=/run/user/1000/bus", null, true)]
    [InlineData("unix:path=/run/user/1000//bus", null, true)]
    [InlineData("unix:path=/run/user/1000/x/../bus", null, true)]
    [InlineData("unix:path=/xdg/runtime/bus", null, true)]
    [InlineData("unix:path=/srv/session-bus,guid=99", "unix:path=/srv/session-bus", true)]
    [InlineData("unix:path=/srv/other", "unix:path=/srv/a;unix:path=/srv/other", true)]
    // Addresses that cannot be shown to be test-owned: abstract, directory, TCP, lists, escapes, relative paths.
    [InlineData("unix:abstract=/tmp/dbus-1", null, true)]
    [InlineData("unix:tmpdir=/tmp", null, true)]
    [InlineData("unix:runtime=yes", null, true)]
    [InlineData("tcp:host=localhost,port=4000", null, true)]
    [InlineData("unix:path=/nonexistent/a;unix:path=/nonexistent/b", null, true)]
    [InlineData("unix:path=/nonexistent/%62us", null, true)]
    [InlineData("unix:path=relative/bus", null, true)]
    [InlineData("unix:path=/nonexistent/a,path=/nonexistent/b", null, true)]
    [InlineData("launchd:env=DBUS_LAUNCHD_SESSION_BUS_SOCKET", null, true)]
    // Test-owned: a path that does not exist.
    [InlineData("unix:path=/nonexistent/arcforges-test-bus", null, false)]
    [InlineData("unix:path=/nonexistent/arcforges-test-bus,guid=abc", "unix:path=/run/user/1000/bus", false)]
    public void TheSecretServiceScopeIsTheUserSessionBusAndOnlyTestOwnedAddressesAreOutside(string address, string? session,
        bool inScope) =>
        Assert.Equal(inScope, OsSecretStoreGuard.IsUserSessionBus(address, session, "/xdg/runtime", 1000, "/nonexistent-temp"));

    [Fact(Skip = LinuxOnly, SkipUnless = nameof(OnLinux))]
    [SupportedOSPlatform("linux")]
    public void AnExistingSocketIsTestOwnedOnlyInADirectoryOfItsOwnUnderTheTemporaryDirectory()
    {
        // Real sockets on this test's own temporary paths; no bus is contacted.
        string temporary = Path.GetTempPath();
        string ownSocket = Path.Combine(_root, "bus");
        using var own = Listen(ownSocket);
        Assert.False(OsSecretStoreGuard.IsUserSessionBus("unix:path=" + ownSocket + ",guid=1", null, null, 1000, temporary));
        // The same socket is in scope when it is the environment's session bus or $XDG_RUNTIME_DIR/bus.
        Assert.True(OsSecretStoreGuard.IsUserSessionBus("unix:path=" + ownSocket, "unix:path=" + ownSocket, null, 1000, temporary));
        Assert.True(OsSecretStoreGuard.IsUserSessionBus("unix:path=" + ownSocket, null, _root, 1000, temporary));
        // An existing socket outside a directory of its own under the temporary directory cannot be shown to be test-owned.
        Assert.True(OsSecretStoreGuard.IsUserSessionBus("unix:path=" + ownSocket, null, null, 1000, Path.Combine(_root, "elsewhere")));
        Assert.True(OsSecretStoreGuard.IsUserSessionBus("unix:path=" + ownSocket, null, null, 1000, _root));
    }

    [Fact(Skip = LinuxOnly, SkipUnless = nameof(OnLinux))]
    [SupportedOSPlatform("linux")]
    public void ASymbolicLinkIsJudgedByItsRealTargetSoALinkIntoTheUserRuntimeDirectoryIsInScope()
    {
        // Links in this test's own temporary directory; their targets are only read, never opened, and no bus is contacted. The
        // user bus is /run/user/1000/bus by the arguments below, whether or not it exists here.
        string temporary = Path.GetTempPath();
        string userBus = Path.Combine(_root, "user-bus");
        File.CreateSymbolicLink(userBus, "/run/user/1000/bus");
        string runtimeDirectory = Path.Combine(_root, "runtime-directory");
        Directory.CreateSymbolicLink(runtimeDirectory, "/run/user/1000");
        string chained = Path.Combine(_root, "chained");
        File.CreateSymbolicLink(chained, "user-bus");
        string viaParent = Path.Combine(_root, "parent-link");
        Directory.CreateSymbolicLink(viaParent, Path.Combine(_root, "runtime-directory"));
        foreach (string inScope in new[] { userBus, Path.Combine(runtimeDirectory, "bus"), chained, Path.Combine(viaParent, "bus"),
            Path.Combine(_root, "x", "..", "user-bus") })
        {
            Assert.True(OsSecretStoreGuard.IsUserSessionBus("unix:path=" + inScope, null, null, 1000, temporary), inScope);
        }

        // A link loop cannot be resolved, so it is in scope.
        string loop = Path.Combine(_root, "loop");
        File.CreateSymbolicLink(loop, "loop");
        Assert.True(OsSecretStoreGuard.IsUserSessionBus("unix:path=" + loop, null, null, 1000, temporary));
        Assert.Null(OsSecretStoreGuard.ResolveLinks(loop));

        // A link to this test's own socket stays test-owned, and a link to a path that does not exist reaches nothing.
        string ownSocket = Path.Combine(_root, "bus");
        using var own = Listen(ownSocket);
        string alias = Path.Combine(_root, "alias");
        File.CreateSymbolicLink(alias, ownSocket);
        Assert.Equal(ownSocket, OsSecretStoreGuard.ResolveLinks(alias));
        Assert.False(OsSecretStoreGuard.IsUserSessionBus("unix:path=" + alias, null, null, 1000, temporary));
        string nowhere = Path.Combine(_root, "nowhere");
        File.CreateSymbolicLink(nowhere, "/nonexistent/arcforges-test-bus");
        Assert.False(OsSecretStoreGuard.IsUserSessionBus("unix:path=" + nowhere, null, null, 1000, temporary));
    }

    [SupportedOSPlatform("linux")]
    private static System.Net.Sockets.Socket Listen(string path)
    {
        var socket = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.Unix, System.Net.Sockets.SocketType.Stream,
            System.Net.Sockets.ProtocolType.Unspecified);
        socket.Bind(new System.Net.Sockets.UnixDomainSocketEndPoint(path));
        return socket;
    }
}
