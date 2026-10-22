// SPDX-License-Identifier: AGPL-3.0-only

using System.Text.Json;
using System.Text.RegularExpressions;

namespace ArcForges.Tests.ArchitectureTests;

/// <summary>
/// The repository check of the OS secret-store test guard (ArcForges-Design 16-testing-strategy section 1, guard item 3; AD-0016
/// amendment of 2026-10-17). It runs in the host verification and in external-PR CI with the other architecture tests.
/// </summary>
public sealed partial class OsSecretStoreTierPolicyTests
{
    private const string TierDirectory = "tests/OsSecretStoreTests/";
    private const string TierProject = "tests/OsSecretStoreTests/ArcForges.Tests.OsSecretStoreTests.csproj";
    private const string TierWorkflow = ".github/workflows/os-secret-store-tier.yml";
    private const string TierRunner = "eng/os_secret_store_tier.py";
    private const string GuardScriptTest = "eng/test_os_secret_store_guard.py";
    private const string SecretsLibrary = "src/BuildingBlocks/ArcForges.Security.Secrets/";
    private const string ThisFile = "tests/ArchitectureTests/OsSecretStoreTierPolicyTests.cs";
    private const string OptIn = "ARCFORGES_OS_SECRET_STORE_TESTS";
    private const string DenySwitch = "ArcForges.Security.Secrets.DenyOsStores";
    private const string TierCondition = "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' || "
        + "github.event_name == 'merge_group' || (github.event_name == 'pull_request' && github.event.pull_request.user.login != 'deku2026')";

    private static readonly string Root = FindRoot();

    /// <summary>
    /// The reviewed allow-list: test, tool or benchmark sources outside the tier that name the real adapters, each with the reason
    /// it cannot reach the user's store. Every entry must still contain such a reference, so the list cannot go stale.
    /// </summary>
    private static readonly Dictionary<string, string> AllowList = new(StringComparer.Ordinal)
    {
        ["src/BuildingBlocks/ArcForges.Security.Secrets/Tests/LinuxSecretStoreSelectionTests.cs"] =
            "Linux selection tests over a test-owned bus: every selection names a bus address that does not exist; the tripwire refuses "
            + "any other address, so they cannot reach the user's session bus.",
        ["src/BuildingBlocks/ArcForges.Security.Secrets/Tests/SecretBrokerTests.cs"] =
            "The strict Linux entry point over a bus address that does not exist, and the Windows target validation through reflection "
            + "on a static method; neither constructs an adapter or makes an OS call.",
        ["src/BuildingBlocks/ArcForges.Security.Secrets/Tests/OsSecretStoreGuardTests.cs"] =
            "The negative tests of the guard: each refused call makes no OS call even without the tripwire (a constructor, a "
            + "non-canonical target, a selection that only constructs, or no session bus at all).",
        ["tests/SecretStoreSelectionAotTests/Program.cs"] =
            "The Native AOT compile probe of the selection; CI never runs it. On Windows a run is refused by the tripwire (its runtime "
            + "configuration sets the switch); on Linux it supplies only test-owned buses.",
        ["tests/ArchitectureTests/RepositoryPolicyTests.cs"] =
            "The closed native binding map names the Credential Manager exports (CredReadW, CredWriteW, CredDeleteW, CredFree) as data "
            + "for their single owner; it calls nothing.",
        [ThisFile] = "This check's own patterns.",
    };

    [Xunit.Fact]
    public void TestToolAndBenchmarkSourcesOutsideTheTierNeverNameTheRealOsStores()
    {
        var offenders = new List<string>();
        var allowedHits = new HashSet<string>(StringComparer.Ordinal);
        foreach (string path in Sources().Where(path => !IsProduction(path) && !InTier(path)))
        {
            string text = File.ReadAllText(Path.Combine(Root, path));
            bool references = AdapterReference().IsMatch(text) || DirectStoreAccess().IsMatch(text);
            if (!references) continue;
            if (AllowList.ContainsKey(path)) allowedHits.Add(path);
            else offenders.Add(path);
        }

        Xunit.Assert.True(offenders.Count == 0, "Only the OS secret-store tier (" + TierDirectory + ") may name OsSecretStore.*, "
            + "WindowsCredentialManagerSecretStore, SecretServiceSecretStore, the Cred* API or cmdkey: " + string.Join(", ", offenders));
        Xunit.Assert.Equal(AllowList.Keys.Order(StringComparer.Ordinal), allowedHits.Order(StringComparer.Ordinal));
        Xunit.Assert.All(AllowList.Values, reason => Xunit.Assert.False(string.IsNullOrWhiteSpace(reason)));
    }

    [Xunit.Theory]
    [Xunit.InlineData("var store = ArcForges.Security.Secrets.OsSecretStore.CreateForCurrentPlatform();")]
    [Xunit.InlineData("_ = global::ArcForges.Security.Secrets.OsSecretStore.SelectForCurrentPlatform(root);")]
    [Xunit.InlineData("using static ArcForges.Security.Secrets.OsSecretStore;")]
    [Xunit.InlineData("using S = ArcForges.Security.Secrets.OsSecretStore;")]
    [Xunit.InlineData("var type = typeof(OsSecretStore);")]
    [Xunit.InlineData("string name = nameof(OsSecretStore);")]
    [Xunit.InlineData("OsSecretStore . CreateForCurrentPlatform()")]
    [Xunit.InlineData("new ArcForges.Security.Secrets.WindowsCredentialManagerSecretStore()")]
    [Xunit.InlineData("using W = global::ArcForges.Security.Secrets.WindowsCredentialManagerSecretStore;")]
    [Xunit.InlineData("var type = typeof(global::ArcForges.Security.Secrets.SecretServiceSecretStore);")]
    [Xunit.InlineData("using static ArcForges.Security.Secrets.SecretServiceSecretStore;")]
    public void TheReferenceCheckCatchesEveryFormOfNamingTheAdaptersAndTheirSelection(string source) =>
        Xunit.Assert.Matches(AdapterReference(), source);

    [Xunit.Theory]
    [Xunit.InlineData("if (OsSecretStoreGuard.IsDenied) return;")]
    [Xunit.InlineData("OsSecretStoreGuard.ThrowIfDenied(\"a CNG user key store\");")]
    [Xunit.InlineData("catch (ArcForges.Security.Secrets.OsSecretStoreDeniedException) { }")]
    [Xunit.InlineData("tests/OsSecretStoreTests/ArcForges.Tests.OsSecretStoreTests.csproj")]
    [Xunit.InlineData("public sealed partial class OsSecretStoreTierPolicyTests")]
    public void TheReferenceCheckIgnoresTheGuardItsErrorAndTheTierName(string source) =>
        Xunit.Assert.DoesNotMatch(AdapterReference(), source);

    [Xunit.Theory]
    [Xunit.InlineData("CredReadW(target, 1, 0, out var credential)")]
    [Xunit.InlineData("[LibraryImport(\"Advapi32.dll\", EntryPoint = \"CredEnumerateW\")]")]
    [Xunit.InlineData("Process.Start(\"cmdkey.exe\", \"/list\")")]
    [Xunit.InlineData("secret-tool lookup application arcforges")]
    public void TheDirectStoreCheckCatchesTheCredentialApiAndTheStoreClients(string source) =>
        Xunit.Assert.Matches(DirectStoreAccess(), source);
    [Xunit.Fact]
    public void ProductionSourcesNameTheAdaptersOnlyInTheirOwnLibrary()
    {
        // DesktopPlatform has no composition root of its own: the node (ArcForges) composes the store. The adapters, their selection
        // and the Credential Manager API therefore appear in production sources only inside ArcForges.Security.Secrets.
        var offenders = Sources().Where(path => IsProduction(path) && !path.StartsWith(SecretsLibrary, StringComparison.Ordinal))
            .Where(path =>
            {
                string text = File.ReadAllText(Path.Combine(Root, path));
                return AdapterReference().IsMatch(text) || DirectStoreAccess().IsMatch(text);
            })
            .ToList();
        Xunit.Assert.True(offenders.Count == 0, "Production sources outside " + SecretsLibrary + " name a real OS store: "
            + string.Join(", ", offenders));
    }

    [Xunit.Fact]
    public void OnlyTheTiersOwnSuiteSelectsTheTiersTests()
    {
        // The tier project is named by no workflow, hook or script except the tier's own workflow and runner (and the guard's unittest,
        // which asserts that no routine suite contains it), and no other project references it.
        string tierName = Path.GetFileNameWithoutExtension(TierProject);
        var selectors = TrackedFiles().Where(path => path.StartsWith(".github/workflows/", StringComparison.Ordinal)
            || path.StartsWith(".githooks/", StringComparison.Ordinal)
            || (path.StartsWith("eng/", StringComparison.Ordinal) && path.EndsWith(".py", StringComparison.Ordinal)));
        foreach (string path in selectors)
        {
            string text = File.ReadAllText(Path.Combine(Root, path));
            // Workflows, hooks and the verification scripts may not name the tier at all; any other eng script may not put it on a
            // dotnet command line (a policy test may name the project as data, for example a digest of its project file).
            bool names = text.Contains("OsSecretStoreTests", StringComparison.Ordinal) || text.Contains(tierName, StringComparison.Ordinal);
            bool strict = !path.EndsWith(".py", StringComparison.Ordinal) || path.StartsWith("eng/verify", StringComparison.Ordinal);
            bool selects = strict ? names : text.Split('\n').Any(line => line.Contains("dotnet", StringComparison.Ordinal)
                && line.Contains("OsSecretStoreTests", StringComparison.Ordinal));
            Xunit.Assert.True(!selects || path is TierWorkflow or TierRunner or GuardScriptTest, path + " selects the OS secret-store tier");
            // No workflow, hook or script runs a whole solution or directory, which could select the tier: every `dotnet test` names one
            // project (command lines in workflows and hooks, argument lists in the Python scripts).
            if (!path.EndsWith(".py", StringComparison.Ordinal))
            {
                Xunit.Assert.True(Regex.Count(text, @"\bdotnet\s+test\b") == Regex.Count(text, @"\bdotnet\s+test\s+--project\s+\S"),
                    path + " runs `dotnet test` without --project");
            }

            Xunit.Assert.True(Regex.Count(text, "\"dotnet\",\\s*\"test\"") == Regex.Count(text, "\"dotnet\",\\s*\"test\",\\s*\"--project\""),
                path + " runs `dotnet test` without --project");
        }

        foreach (string project in TrackedFiles().Where(path => path.EndsWith(".csproj", StringComparison.Ordinal) && path != TierProject))
        {
            var references = System.Xml.Linq.XDocument.Load(Path.Combine(Root, project)).Descendants("ProjectReference")
                .Select(reference => reference.Attribute("Include")?.Value ?? string.Empty);
            Xunit.Assert.DoesNotContain(references, reference => reference.Contains("OsSecretStoreTests", StringComparison.Ordinal));
        }

        // Every test class of the tier carries the tier's trait, and no test outside the tier does.
        foreach (string path in Sources().Where(path => path.EndsWith(".cs", StringComparison.Ordinal)))
        {
            string text = File.ReadAllText(Path.Combine(Root, path));
            bool hasTests = text.Contains("[Fact", StringComparison.Ordinal) || text.Contains("[Theory", StringComparison.Ordinal);
            bool trait = TierTrait().IsMatch(text);
            if (InTier(path) && hasTests) Xunit.Assert.True(trait, path + " lacks [Trait(\"env\", \"os-secret-store\")]");
            if (!InTier(path) && path != ThisFile) Xunit.Assert.False(trait, path + " carries the OS secret-store tier's trait");
        }

        // The tier workflow builds and runs only the tier project.
        string workflow = File.ReadAllText(Path.Combine(Root, TierWorkflow));
        foreach (Match command in DotnetProjectCommand().Matches(workflow))
        {
            Xunit.Assert.Equal(TierProject, command.Groups["project"].Value);
        }

        Xunit.Assert.Contains("dotnet test --project " + TierProject, workflow, StringComparison.Ordinal);
    }

    [Xunit.Fact]
    public void TheOptInIsSetOnlyOnTheHostedTierJobsTestStepUnderTheAmendedCondition()
    {
        foreach (string path in TrackedFiles().Where(path => path.StartsWith(".github/", StringComparison.Ordinal) && path != TierWorkflow))
        {
            Xunit.Assert.DoesNotContain(OptIn, File.ReadAllText(Path.Combine(Root, path)), StringComparison.Ordinal);
        }

        string[] lines = File.ReadAllLines(Path.Combine(Root, TierWorkflow));
        var settings = lines.Select((line, index) => (line, index))
            .Where(item => item.line.Contains(OptIn, StringComparison.Ordinal) && !item.line.TrimStart().StartsWith('#')).ToList();
        Xunit.Assert.Single(settings);
        var (setting, at) = settings[0];
        Xunit.Assert.Equal("          " + OptIn + ": '1'", setting);
        // Its parent is a step's env (8 spaces), never a job's (4) or the workflow's (0), and that step runs the tier's tests.
        int parent = Enumerable.Range(0, at).Reverse().First(index => Indent(lines[index]) < Indent(setting) && lines[index].Trim().Length > 0);
        Xunit.Assert.Equal("        env:", lines[parent]);
        int step = Enumerable.Range(0, parent).Reverse().First(index => lines[index].StartsWith("      - ", StringComparison.Ordinal));
        int next = Enumerable.Range(at + 1, lines.Length - at - 1).FirstOrDefault(index => lines[index].StartsWith("      - ", StringComparison.Ordinal)
            || Indent(lines[index]) < 6 && lines[index].Trim().Length > 0, lines.Length);
        string body = string.Join('\n', lines[step..next]);
        Xunit.Assert.Contains("dotnet test --project " + TierProject, body, StringComparison.Ordinal);

        // Triggers and the job condition of the AD-0016 amendment: external PRs, merge_group, dispatch and a weekly schedule; never
        // a push, and skipped for the owner's PRs.
        string workflow = string.Join('\n', lines);
        string triggers = workflow.Split("\non:\n", 2)[1].Split("\npermissions:", 2)[0];
        Xunit.Assert.Equal(["merge_group", "pull_request", "schedule", "workflow_dispatch"],
            TopLevelTrigger().Matches(triggers).Select(match => match.Groups["name"].Value).Order(StringComparer.Ordinal));
        Xunit.Assert.Contains("- cron: ", triggers, StringComparison.Ordinal);
        var conditions = JobCondition().Matches(workflow).Select(match => match.Groups["condition"].Value.Trim()).ToList();
        Xunit.Assert.NotEmpty(conditions);
        Xunit.Assert.All(conditions, condition => Xunit.Assert.Equal("${{ " + TierCondition + " }}", condition));
        Xunit.Assert.Contains("runs-on: windows-latest", workflow, StringComparison.Ordinal);
    }

    [Xunit.Fact]
    public void EveryTestProjectDeniesTheOsStoresAndNoProductionProjectDoes()
    {
        // This test process itself (the architecture tests are a test project).
        Xunit.Assert.True(AppContext.TryGetSwitch(DenySwitch, out bool deny) && deny);
        string targets = File.ReadAllText(Path.Combine(Root, "Directory.Build.targets"));
        Xunit.Assert.Contains("<RuntimeHostConfigurationOption Include=\"" + DenySwitch + "\" Value=\"true\" />", targets, StringComparison.Ordinal);

        // The built runtime configuration of every project in the solution: the Test role sets the switch, production never does.
        // The gate builds the whole solution first; a test project without a build output fails here instead of passing unchecked.
        var outputs = new DirectoryInfo(AppContext.BaseDirectory);
        string configuration = outputs.Parent!.Name;
        string binaries = outputs.Parent!.Parent!.Parent!.FullName;
        using var projects = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, "eng", "policy", "architecture-projects.json")));
        string solution = File.ReadAllText(Path.Combine(Root, "DesktopPlatform.slnx"));
        int checkedTests = 0;
        foreach (var project in projects.RootElement.EnumerateArray())
        {
            string path = project.GetProperty("path").GetString()!;
            if (!solution.Contains("\"" + path + "\"", StringComparison.Ordinal)) continue;
            bool test = project.GetProperty("role").GetString() == "Test";
            bool production = project.GetProperty("production").GetBoolean();
            // The project's own runtime configuration (a test output also holds copies of the helpers it starts).
            string directory = Path.Combine(binaries, Path.GetFileNameWithoutExtension(path), configuration);
            string own = AssemblyName(path) + ".runtimeconfig.json";
            var configurations = Directory.Exists(directory)
                ? Directory.EnumerateFiles(directory, own, SearchOption.AllDirectories).ToList()
                : [];
            if (test)
            {
                Xunit.Assert.True(configurations.Count > 0 || !IsExecutable(path), path + " has no built runtime configuration in "
                    + directory + "; build DesktopPlatform.slnx (" + configuration + ") first");
                Xunit.Assert.All(configurations, file => Xunit.Assert.True(Denies(file), file + " does not set " + DenySwitch));
                checkedTests += configurations.Count > 0 ? 1 : 0;
            }
            else if (production)
            {
                Xunit.Assert.All(configurations, file => Xunit.Assert.False(Denies(file), file + " (production) sets " + DenySwitch));
            }
        }

        Xunit.Assert.True(checkedTests >= 20, "only " + checkedTests + " test projects were checked");
    }

    private static bool Denies(string runtimeConfiguration)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(runtimeConfiguration));
        return document.RootElement.TryGetProperty("runtimeOptions", out var options)
            && options.TryGetProperty("configProperties", out var properties)
            && properties.TryGetProperty(DenySwitch, out var value)
            && value.ValueKind == JsonValueKind.True;
    }

    private static bool IsExecutable(string project)
    {
        string text = File.ReadAllText(Path.Combine(Root, project));
        return text.Contains("<OutputType>Exe</OutputType>", StringComparison.Ordinal)
            || text.Contains("<IsTestProject>true</IsTestProject>", StringComparison.Ordinal);
    }

    private static string AssemblyName(string project) =>
        System.Xml.Linq.XDocument.Load(Path.Combine(Root, project)).Descendants("AssemblyName").Select(name => name.Value).FirstOrDefault()
        ?? Path.GetFileNameWithoutExtension(project);

    private static int Indent(string line) => line.Length - line.TrimStart(' ').Length;

    // Test, tool and benchmark sources are everything outside src/, and the Tests/ and Fixture/ directories inside it.
    private static bool IsProduction(string path) => path.StartsWith("src/", StringComparison.Ordinal)
        && !path.Contains("/Tests/", StringComparison.Ordinal) && !path.Contains("/Fixture/", StringComparison.Ordinal);

    private static bool InTier(string path) => path.StartsWith(TierDirectory, StringComparison.Ordinal) || path == TierRunner;

    private static IEnumerable<string> Sources() => TrackedFiles().Where(path => path.EndsWith(".cs", StringComparison.Ordinal)
        || path.EndsWith(".py", StringComparison.Ordinal) || path.EndsWith(".ps1", StringComparison.Ordinal)
        || path.EndsWith(".sh", StringComparison.Ordinal) || path.EndsWith(".cpp", StringComparison.Ordinal)
        || path.EndsWith(".h", StringComparison.Ordinal));

    private static IEnumerable<string> TrackedFiles() =>
        Directory.EnumerateFiles(Root, "*", SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(Root, path).Replace('\\', '/'))
            .Where(path => !path.Split('/').Any(part => part is ".git" or ".worktree" or "artifacts" or "bin" or "obj"));

    private static string FindRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "DesktopPlatform.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("DesktopPlatform root not found.");
    }

    // The bare type names in any form (qualified, global::, using static, aliases, typeof/nameof, member access); a word character
    // after the name (OsSecretStoreGuard, OsSecretStoreDeniedException, OsSecretStoreTests) is another identifier.
    [GeneratedRegex(@"\bOsSecretStore\b|\bWindowsCredentialManagerSecretStore\b|\bSecretServiceSecretStore\b")]
    private static partial Regex AdapterReference();

    [GeneratedRegex(@"\bCred(?:Read|Write|Delete|Enumerate|Free|Rename|GetTargetInfo)[AW]?\b|\bcmdkey\b|\bsecret-tool\b", RegexOptions.IgnoreCase)]
    private static partial Regex DirectStoreAccess();

    [GeneratedRegex(@"\[Trait\(\s*""env""\s*,\s*""os-secret-store""\s*\)\]")]
    private static partial Regex TierTrait();

    [GeneratedRegex(@"\bdotnet\s+(?:restore|build|test(?:\s+--project)?)\s+(?<project>[^\s]+\.csproj)")]
    private static partial Regex DotnetProjectCommand();

    [GeneratedRegex(@"^  (?<name>[a-z_]+):", RegexOptions.Multiline)]
    private static partial Regex TopLevelTrigger();

    [GeneratedRegex(@"^    if: (?<condition>.+)$", RegexOptions.Multiline)]
    private static partial Regex JobCondition();
}
