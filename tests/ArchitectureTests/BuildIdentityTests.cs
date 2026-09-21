// SPDX-License-Identifier: AGPL-3.0-only

using System.Diagnostics;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Xml.Linq;

namespace ArcForges.Tests.ArchitectureTests;

public sealed class BuildIdentityTests
{
    [Xunit.Fact]
    public void EveryOwnedAssemblyContainsTheActualSourceAndBuildIdentity()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "DesktopPlatform.slnx")))
        {
            root = root.Parent;
        }

        Xunit.Assert.NotNull(root);
        string commit = Git(root.FullName, "rev-parse", "HEAD");
        string epoch = Git(root.FullName, "show", "-s", "--format=%ct", "HEAD");
        bool ci = Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true";
        string build = ci ? Environment.GetEnvironmentVariable("GITHUB_RUN_ID") + "." + Environment.GetEnvironmentVariable("GITHUB_RUN_ATTEMPT") : "local." + commit;
        string pipeline = ci ? "https://github.com/" + Environment.GetEnvironmentVariable("GITHUB_REPOSITORY") + "/actions/runs/" + Environment.GetEnvironmentVariable("GITHUB_RUN_ID") : "local";
        string host = OperatingSystem.IsWindows() ? "windows" : OperatingSystem.IsMacOS() ? "macos" : "linux";
        var solution = XDocument.Load(Path.Combine(root.FullName, "DesktopPlatform.slnx"));
        foreach (var project in solution.Descendants("Project"))
        {
            string name = Path.GetFileNameWithoutExtension(project.Attribute("Path")!.Value);
            string path = Path.Combine(root.FullName, "artifacts", "bin", "dotnet", host, name, "Release", "net10.0", name + ".dll");
            using var stream = File.OpenRead(path);
            using var pe = new PEReader(stream);
            var reader = pe.GetMetadataReader();
            var values = new Dictionary<string, string?>(StringComparer.Ordinal);
            foreach (var handle in reader.GetAssemblyDefinition().GetCustomAttributes())
            {
                var attribute = reader.GetCustomAttribute(handle);
                if (attribute.Constructor.Kind != HandleKind.MemberReference)
                {
                    continue;
                }

                var member = reader.GetMemberReference((MemberReferenceHandle)attribute.Constructor);
                if (member.Parent.Kind != HandleKind.TypeReference)
                {
                    continue;
                }

                var type = reader.GetTypeReference((TypeReferenceHandle)member.Parent);
                if (reader.GetString(type.Name) != "AssemblyMetadataAttribute" || reader.GetString(type.Namespace) != "System.Reflection")
                {
                    continue;
                }

                var blob = reader.GetBlobReader(attribute.Value);
                Xunit.Assert.Equal(1, blob.ReadUInt16());
                string key = blob.ReadSerializedString()!;
                if (key.StartsWith("ArcForges.", StringComparison.Ordinal))
                {
                    values.Add(key, blob.ReadSerializedString());
                }
            }

            Xunit.Assert.Equal(commit, values["ArcForges.SourceCommit"]);
            Xunit.Assert.Equal(epoch, values["ArcForges.SourceDateEpoch"]);
            Xunit.Assert.Equal(build, values["ArcForges.BuildId"]);
            Xunit.Assert.Equal(pipeline, values["ArcForges.PipelineRun"]);
            Xunit.Assert.Equal(ci ? "ci" : "local", values["ArcForges.BuildKind"]);
        }
    }

    private static string Git(string directory, params string[] arguments)
    {
        var start = new ProcessStartInfo("git") { WorkingDirectory = directory, RedirectStandardOutput = true, UseShellExecute = false };
        foreach (string argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)!;
        string result = process.StandardOutput.ReadToEnd().Trim();
        process.WaitForExit();
        Xunit.Assert.Equal(0, process.ExitCode);
        return result;
    }
}
