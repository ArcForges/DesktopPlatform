// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Security.Secrets;
using Xunit;

// One test at a time, in one process: the tier never runs tests in parallel (ArcForges-Design 16-testing-strategy section 1).
[assembly: Xunit.v3.Parallelization(Mode = Xunit.Sdk.ParallelMode.None)]

namespace ArcForges.Tests.OsSecretStoreTests;

/// <summary>The single, non-parallel collection of every tier test; the tier fixture is shared by all of them.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
[SuppressMessage("Maintainability", "CA1515:Consider making public types internal", Justification = "xunit collection definitions are public.")]
public sealed class OsSecretStoreTierDefinition : ICollectionFixture<OsSecretStoreTier>
{
    public const string Name = "os-secret-store tier";
}

/// <summary>
/// The fixture of the OS secret-store integration tier (ArcForges-Design 16-testing-strategy section 1). It is the only way the
/// tier's tests reach a store, and it enforces the tier's rules for the whole run:
/// <list type="bullet">
/// <item>the single opt-in <c>ARCFORGES_OS_SECRET_STORE_TESTS=1</c> (otherwise the tests are reported as not run, with that reason);</item>
/// <item>canonical, unique entry names: <c>ArcForges.Secrets.v1.</c> plus the uppercase SHA-256 hex of
/// <c>arcforges.os-secret-store-test.v1|&lt;run id&gt;|&lt;n&gt;</c> with a fresh random run id;</item>
/// <item>the run's name list, written and flushed before each entry is created and kept as the run's evidence;</item>
/// <item>hard limits: at most 4 entries existing at once, 32 secret-store calls, 10 s per call and 5 minutes for the tier;
/// reaching one fails the run, and every later call fails with the same reason;</item>
/// <item>exact-name cleanup from the list only, each deletion followed by a read-back that must find the entry absent; a failed
/// absence check is evidence (L-26), reported by name and never retried. Nothing is enumerated or deleted by pattern.</item>
/// </list>
/// </summary>
[SuppressMessage("Maintainability", "CA1515:Consider making public types internal", Justification = "The fixture of public xunit test classes.")]
public sealed class OsSecretStoreTier : IDisposable
{
    public const int MaximumLiveEntries = 4;
    public const int MaximumCalls = 32;
    public const string NamePrefix = "ArcForges.Secrets.v1.";
    public const string NameDomain = "arcforges.os-secret-store-test.v1";
    public const string WindowsTierReason =
        "OS secret-store tier: runs only on Windows with ARCFORGES_OS_SECRET_STORE_TESTS=1 (the hosted tier job or eng/os_secret_store_tier.py).";
    public const string LinuxTierReason =
        "OS secret-store tier: runs only on Linux in the isolated ArcForgesTest WSL distribution with ARCFORGES_OS_SECRET_STORE_TESTS=1 (eng/os_secret_store_tier.py).";

    public static readonly TimeSpan CallTimeout = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan TierTimeout = TimeSpan.FromMinutes(5);

    private readonly Stopwatch _elapsed = Stopwatch.StartNew();
    private readonly Lock _gate = new();
    private readonly Dictionary<string, ISecretBackingStore?> _live = new(StringComparer.Ordinal);
    private readonly HashSet<string> _listed = new(StringComparer.Ordinal);
    private int _next;
    private int _calls;
    private string? _failure;

    public OsSecretStoreTier()
    {
        RunId = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        NameList = Path.Combine(EvidenceDirectory(), "os-secret-store-tier-" + RunId + ".log");
    }

    /// <summary>Whether this process carries the tier's opt-in.</summary>
    public static bool OptedIn => Environment.GetEnvironmentVariable(OsSecretStoreGuard.OptInVariable) == "1";

    /// <summary>The Windows Credential Manager tests run.</summary>
    public static bool WindowsTier => OperatingSystem.IsWindows() && OptedIn;

    /// <summary>The Linux Secret Service tests run: never in the development distribution or a user's session keyring.</summary>
    public static bool LinuxTier => OperatingSystem.IsLinux() && OptedIn
        && Environment.GetEnvironmentVariable("WSL_DISTRO_NAME") == "ArcForgesTest";

    /// <summary>The fresh random run id that every entry name of this run is derived from.</summary>
    public string RunId { get; }

    /// <summary>The run's name list (evidence): every entry name, written before the entry is created, and what became of it.</summary>
    public string NameList { get; }

    /// <summary>The secret-store calls made so far in this run.</summary>
    public int Calls
    {
        get
        {
            lock (_gate) return _calls;
        }
    }

    /// <summary>The canonical name of the run's n-th entry.</summary>
    public static string EntryName(string runId, int n) => NamePrefix + Convert.ToHexString(SHA256.HashData(
        Encoding.UTF8.GetBytes(NameDomain + "|" + runId + "|" + n.ToString(CultureInfo.InvariantCulture))));

    /// <summary>
    /// The next entry name, recorded in the name list (and flushed) before the caller creates it. <paramref name="store"/> is the
    /// store the entry will live in; the fixture deletes it there, by exact name, if the test does not.
    /// </summary>
    public string NewEntry(ISecretBackingStore? store)
    {
        string name;
        lock (_gate)
        {
            Check();
            if (_live.Count >= MaximumLiveEntries)
            {
                Fail($"the limit of {MaximumLiveEntries} test entries existing at once was reached");
            }

            name = EntryName(RunId, ++_next);
            _listed.Add(name);
            _live.Add(name, store);
            Record("listed", name);
        }

        return name;
    }

    /// <summary>One secret-store call, counted and bounded by <see cref="CallTimeout"/>.</summary>
    public T Call<T>(string operation, Func<T> call)
    {
        ArgumentNullException.ThrowIfNull(call);
        lock (_gate)
        {
            Check();
            if (_elapsed.Elapsed + CallTimeout > TierTimeout) Fail($"the tier's {TierTimeout.TotalMinutes:0} minutes would be exceeded");
            if (_calls >= MaximumCalls) Fail($"the limit of {MaximumCalls} secret-store calls was reached before '{operation}'");
            _calls++;
        }

        var task = Task.Run(call);
        if (!((IAsyncResult)task).AsyncWaitHandle.WaitOne(CallTimeout))
        {
            lock (_gate) Fail($"'{operation}' did not finish within {CallTimeout.TotalSeconds:0} s");
        }

        return task.GetAwaiter().GetResult();
    }

    /// <summary>As <see cref="Call{T}(string, Func{T})"/> for a call without a result.</summary>
    public void Call(string operation, Action call)
    {
        ArgumentNullException.ThrowIfNull(call);
        _ = Call(operation, () =>
        {
            call();
            return true;
        });
    }

    /// <summary>
    /// Deletes a listed entry by its exact name and reads it back once; it must be absent. A remaining entry fails the test with its
    /// name and stays recorded as evidence; it is never deleted again or retried.
    /// </summary>
    public void Remove(string name)
    {
        ISecretBackingStore store;
        lock (_gate)
        {
            if (!_live.TryGetValue(name, out var owner) || owner is null)
            {
                throw new InvalidOperationException("Only a live entry of this run's name list, with its store, can be removed: " + name);
            }

            store = owner;
        }

        try
        {
            _ = Call("delete " + name, () => store.Delete(name));
        }
        catch
        {
            lock (_gate)
            {
                _live.Remove(name);
                Record("DELETE-FAILED (never retried)", name);
            }

            throw;
        }

        try
        {
            VerifyAbsent(name, store);
        }
        finally
        {
            lock (_gate) _live.Remove(name);
        }
    }

    /// <summary>Reads a listed entry back once (test verification): it must be absent. A remaining value fails and is evidence.</summary>
    public void VerifyAbsent(string name, ISecretBackingStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        lock (_gate)
        {
            if (!_listed.Contains(name)) throw new InvalidOperationException("Not an entry of this run's name list: " + name);
        }

        byte[]? remaining = Call("read back " + name, () => store.Read(name));
        lock (_gate)
        {
            _live.Remove(name);
            if (remaining is not null)
            {
                CryptographicOperations.ZeroMemory(remaining);
                Record("ABSENCE-CHECK-FAILED", name);
                Assert.Fail("The OS secret store still returned a value for the deleted test entry " + name
                    + " (evidence, never retried; see " + NameList + ").");
            }

            Record("absent", name);
        }
    }

    /// <summary>
    /// Records that a listed entry needs no deletion because it was never created in a persistent store (its write failed closed,
    /// or its store was a private keyring that the test destroyed with its files).
    /// </summary>
    public void Discard(string name, string reason)
    {
        lock (_gate)
        {
            if (!_live.Remove(name)) throw new InvalidOperationException("Not a live entry of this run's name list: " + name);
            Record("discarded (" + reason + ")", name);
        }
    }

    /// <summary>Removes, once each, the listed entries that a test left behind (exact names only), then reports any that remain.</summary>
    [SuppressMessage("Design", "CA1065:Do not raise exceptions in unexpected locations", Justification =
        "xunit reports a failing fixture cleanup as a failed run, which is what an unverified cleanup must be.")]
    public void Dispose()
    {
        var failures = new List<string>();
        foreach (var (name, store) in Snapshot())
        {
            try
            {
                if (store is null) Discard(name, "no store was attached");
                else Remove(name);
            }
            catch (Exception failure) when (failure is not OutOfMemoryException)
            {
                failures.Add(name + ": " + failure.Message);
            }
        }

        lock (_gate)
        {
            if (_next > 0 || _calls > 0) Record("run ended after " + _calls.ToString(CultureInfo.InvariantCulture) + " secret-store calls", "-");
        }
        if (failures.Count > 0)
        {
            throw new InvalidOperationException("The OS secret-store tier could not verify the cleanup of: " + string.Join("; ", failures));
        }
    }

    private List<(string Name, ISecretBackingStore? Store)> Snapshot()
    {
        lock (_gate) return [.. _live.Select(pair => (pair.Key, pair.Value))];
    }

    private void Check()
    {
        if (!OptedIn) throw new InvalidOperationException("The OS secret-store tier runs only with ARCFORGES_OS_SECRET_STORE_TESTS=1.");
        if (_failure is not null) throw new InvalidOperationException("The OS secret-store tier run already failed: " + _failure);
    }

    [DoesNotReturn]
    private void Fail(string reason)
    {
        _failure ??= reason;
        Record("RUN-FAILED " + reason, "-");
        throw new InvalidOperationException("The OS secret-store tier run failed: " + reason);
    }

    // Each line is appended and flushed to the disk before the call that follows it, so the list survives a crash of the run.
    private void Record(string what, string name)
    {
        string line = string.Create(CultureInfo.InvariantCulture,
            $"{DateTimeOffset.UtcNow:O} run={RunId} n={_next} {what} {name}\n");
        Directory.CreateDirectory(Path.GetDirectoryName(NameList)!);
        using var stream = new FileStream(NameList, FileMode.Append, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough);
        stream.Write(Encoding.UTF8.GetBytes(line));
        stream.Flush(flushToDisk: true);
    }

    private static string EvidenceDirectory()
    {
        string? configured = Environment.GetEnvironmentVariable("ARCFORGES_OS_SECRET_STORE_TESTS_EVIDENCE");
        return !string.IsNullOrWhiteSpace(configured) ? Path.GetFullPath(configured) : Path.Combine(RepositoryRoot(), "artifacts",
            "evidence", "os-secret-store-tier");
    }

    private static string RepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "DesktopPlatform.slnx"))) return directory.FullName;
        }

        return Path.GetTempPath();
    }
}
