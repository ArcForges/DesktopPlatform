// SPDX-License-Identifier: AGPL-3.0-only
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>User-SID ownership, separate from service-mode peer resolution. Real pipe checks are local opt-in, never hosted CI.</summary>
[Collection(LocalRpcCollection.Name)]
[SupportedOSPlatform("windows")]
public sealed class LocalRpcPipeOwnershipTests
{
    private const string WindowsOnly = "Windows security identifiers.";
    private const string OptIn = "Explicit local OS pipe ownership checks only (ARCFORGES_LOCALRPC_OS_STREAMS=1).";

    public static bool IsWindows => OperatingSystem.IsWindows();

    public static bool WindowsEnabled => LocalRpcServiceOsChecks.WindowsEnabled;

    [Fact(Skip = WindowsOnly, SkipUnless = nameof(IsWindows))]
    public void OnlyTheTokenUserSidOwnsTheServerEnd()
    {
        var user = new SecurityIdentifier("S-1-5-21-1000000001-1000000002-1000000003-1001");
        var other = new SecurityIdentifier("S-1-5-21-1000000001-1000000002-1000000003-1002");
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

        Assert.True(LocalRpcClientChannel.OwnerIsUser(user, user));
        Assert.False(LocalRpcClientChannel.OwnerIsUser(other, user));
        Assert.False(LocalRpcClientChannel.OwnerIsUser(administrators, user));
        Assert.False(LocalRpcClientChannel.OwnerIsUser(system, user));
        Assert.False(LocalRpcClientChannel.OwnerIsUser(null, user));
        Assert.False(LocalRpcClientChannel.OwnerIsUser(user, null));
    }

    [Theory(Skip = OptIn, SkipUnless = nameof(WindowsEnabled), Timeout = 60_000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EveryListenerInstanceUsesTheUserSidAndExchangesBytes(bool service)
    {
        var ct = TestContext.Current.CancellationToken;
        using var identity = WindowsIdentity.GetCurrent();
        ReportSession(identity);
        var name = "af-owner-" + Guid.NewGuid().ToString("N");
        await using var source = service ? NamedPipeAcceptSource.BindService(name) : NamedPipeAcceptSource.Bind(name);

        for (var instance = 0; instance < 3; instance++)
        {
            var accepted = source.AcceptAsync(ct).AsTask();
            await using var client = await LocalRpcClientChannel.ConnectNamedPipeAsync(name, ct);
            await using var stream = await accepted.WaitAsync(ServiceHarness.Patience, ct);
            var server = Assert.IsType<NamedPipeServerStream>(stream);
            Assert.Equal(identity.User, server.GetAccessControl().GetOwner(typeof(SecurityIdentifier)));
            var bytes = new byte[1];
            var read = server.ReadAsync(bytes, ct).AsTask();
            await client.WriteAsync(new byte[] { 42 }, ct);
            Assert.Equal(1, await read);
            Assert.Equal(42, bytes[0]);
        }
    }

    [Fact(Skip = OptIn, SkipUnless = nameof(WindowsEnabled), Timeout = 60_000)]
    public async Task TheTokensDefaultOwnerIsAcceptedOnlyWhenItIsTheUser()
    {
        var ct = TestContext.Current.CancellationToken;
        using var identity = WindowsIdentity.GetCurrent();
        ReportSession(identity);
        var name = "af-owner-default-" + Guid.NewGuid().ToString("N");
        await using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        Assert.Equal(identity.Owner, server.GetAccessControl().GetOwner(typeof(SecurityIdentifier)));
        var accepted = server.WaitForConnectionAsync(ct);

        if (identity.Owner != identity.User)
        {
            _ = await Assert.ThrowsAsync<UnauthorizedAccessException>(async () => await LocalRpcClientChannel.ConnectNamedPipeAsync(name, ct));
            await accepted;
            var bytes = new byte[1];
            Assert.Equal(0, await server.ReadAsync(bytes, ct));
        }
        else
        {
            await using var client = await LocalRpcClientChannel.ConnectNamedPipeAsync(name, ct);
            await accepted;
        }
    }

    private static void ReportSession(WindowsIdentity identity) =>
        TestContext.Current.TestOutputHelper?.WriteLine(identity.Owner == identity.User
            ? "Token default owner equals user SID; this run does not prove cross-integrity behavior."
            : "Token default owner differs from user SID; explicit user-owned listeners must still connect.");
}
