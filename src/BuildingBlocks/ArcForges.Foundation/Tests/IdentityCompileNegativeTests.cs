// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Text.Json;
using ArcForges.Contracts.Foundation.Values;
using Xunit;

namespace ArcForges.Foundation.Tests;

public sealed class IdentityCompileNegativeTests
{
    private static readonly string[] CompilerOptions = ["-target:library", "-nologo", "-out:Invalid.dll"];
    [Fact]
    public void PublishedIdentifierKindsCannotBeAssignedOrCompared()
    {
        var directory = Path.Combine(Path.GetTempPath(), "arcforges-identity-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            File.WriteAllText(Path.Combine(directory, "Invalid.cs"), """
                using ArcForges.Contracts.Foundation.Values;
                public static class Invalid {
                  public static void Check(WorkspaceId workspace, CommandId command, InstanceId instance) {
                    RealmId realm = workspace;
                    command = instance;
                    bool equal = workspace == command;
                    bool revisionEqualsSequence = default(ArcForges.Foundation.Revision) == default(ArcForges.Foundation.SequenceNumber);
                    ArcForges.Foundation.Execution.AttemptId attempt = default(ArcForges.Foundation.Execution.InvocationId);
                  }
                }
                """);
            var host = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet";
            var compilerPath = CompileTestSdk.Resolve(host);
            var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
                .Append(Path.Combine(AppContext.BaseDirectory, "ArcForges.Contracts.Foundation.dll"))
                .Append(Path.Combine(AppContext.BaseDirectory, "ArcForges.Foundation.dll")).Distinct(StringComparer.OrdinalIgnoreCase);
            var response = Path.Combine(directory, "compile.rsp");
            File.WriteAllLines(response, CompilerOptions
                .Concat(references.Select(path => "-r:\"" + path + "\""))
                .Append("Invalid.cs"));
            var compiler = new ProcessStartInfo(host)
            {
                WorkingDirectory = directory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            compiler.ArgumentList.Add(compilerPath);
            compiler.ArgumentList.Add("@" + response);
            using var process = Process.Start(compiler)!;
            var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
            process.WaitForExit();
            Assert.NotEqual(0, process.ExitCode);
            Assert.Equal(3, output.Split("error CS0029", StringSplitOptions.None).Length - 1);
            Assert.Equal(2, output.Split("error CS0019", StringSplitOptions.None).Length - 1);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void CompilerSelectionRequiresTheExactPinnedSdkAmongInstalledVersions()
    {
        string[] sdks = ["10.0.401 [sdk-root]", "11.0.100 [sdk-root]", "11.0.101 [sdk-root]", "11.0.200-preview.1 [sdk-root]"];
        Assert.Equal(Path.Combine("sdk-root", "11.0.100", "Roslyn", "bincore", "csc.dll"), CompileTestSdk.Select("11.0.100", sdks));
        Assert.Throws<InvalidOperationException>(() => CompileTestSdk.Select("11.0.102", sdks));
    }
}

internal static class CompileTestSdk
{
    internal static string Resolve(string host)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (!File.Exists(Path.Combine(directory.FullName, "global.json")) && directory.Parent is { } parent)
            directory = parent;
        using var configuration = JsonDocument.Parse(File.ReadAllText(Path.Combine(directory.FullName, "global.json")));
        var version = configuration.RootElement.GetProperty("sdk").GetProperty("version").GetString()
            ?? throw new InvalidOperationException("The repository must pin an SDK version.");
        var query = new ProcessStartInfo(host) { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
        query.ArgumentList.Add("--list-sdks");
        using var process = Process.Start(query)!;
        var lines = process.StandardOutput.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries);
        process.WaitForExit();
        Assert.Equal(0, process.ExitCode);
        var compiler = Select(version, lines);
        Assert.True(File.Exists(compiler), compiler);
        return compiler;
    }

    internal static string Select(string version, IEnumerable<string> lines)
    {
        var sdk = lines.Select(line => line.Trim()).Single(line => line.StartsWith(version + " [", StringComparison.Ordinal));
        var bracket = sdk.IndexOf('[', StringComparison.Ordinal);
        return Path.Combine(sdk[(bracket + 1)..^1], version, "Roslyn", "bincore", "csc.dll");
    }
}
