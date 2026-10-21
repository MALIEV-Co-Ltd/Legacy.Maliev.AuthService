using System.Text.RegularExpressions;

namespace Legacy.Maliev.AuthService.Tests;

/// <summary>
/// Verifies publisher permission scope and source-artifact isolation without executing publishing.
/// </summary>
public sealed class PublishWorkflowPermissionContractTests
{
    /// <summary>
    /// Verifies validation uses the redacted JWT resource scanner.
    /// </summary>
    [Fact]
    public void ValidationWorkflow_UsesRedactedJwtResourceScanner()
    {
        var source = File.ReadAllText(Path.Combine(FindRoot(), ".github", "workflows", "_build-and-test.yml"));
        Assert.Contains(
            "MALIEV-Co-Ltd/Legacy.Maliev.Workflows/actions/dotnet-validate@e3a6093324a24968876782153286f52db8b29fd8",
            source,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "MALIEV-Co-Ltd/Legacy.Maliev.Workflows/actions/dotnet-validate@6017816fa67f369d785ed30794f002cfd6299af7",
            source,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// Verifies stale JWT XML documentation is absent from source.
    /// </summary>
    [Fact]
    public void SourceE2f_StaleJwtXmlDocumentationIsAbsent()
    {
        var root = FindRoot();
        Assert.False(File.Exists(Path.Combine(root, "Maliev.AuthService.JwtSecurity", "Maliev.JwtSecurity.xml")));
        Assert.False(File.Exists(Path.Combine(root, "Maliev.JwtSecurity.xml")));
    }

    /// <summary>
    /// Verifies OpenID Connect permissions are restricted to publisher jobs.
    /// </summary>
    [Fact]
    public void PublishWorkflow_ScopesOidcToPublishJobs()
    {
        AssertWorkflowScopesOidc(File.ReadAllText(Path.Combine(
            FindRoot(),
            ".github",
            "workflows",
            "publish-image.yml")));
    }

    private static void AssertWorkflowScopesOidc(string source)
    {
        var jobsIndex = source.IndexOf("\njobs:", StringComparison.Ordinal);
        Assert.True(jobsIndex > 0, "The publish workflow must define a jobs section.");
        var workflowHeader = source[..jobsIndex];
        Assert.Contains("permissions:", workflowHeader, StringComparison.Ordinal);
        Assert.Contains("  contents: read", workflowHeader, StringComparison.Ordinal);
        Assert.DoesNotContain("id-token: write", workflowHeader, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("actions: read", workflowHeader, StringComparison.OrdinalIgnoreCase);

        var publishJobs = Regex.Matches(
            source,
            @"(?ms)^  publish(?:-[^:\r\n]+)?:\r?\n(?<body>.*?)(?=^  [A-Za-z0-9_-]+:\s*\r?$|\z)");
        Assert.NotEmpty(publishJobs);
        foreach (Match publishJob in publishJobs)
        {
            var job = publishJob.Groups["body"].Value;
            Assert.Contains("permissions:", job, StringComparison.Ordinal);
            Assert.Contains("contents: read", job, StringComparison.Ordinal);
            Assert.Contains("actions: read", job, StringComparison.Ordinal);
            Assert.Contains("id-token: write", job, StringComparison.Ordinal);
        }

        var deploymentGate = Regex.Match(
            source,
            @"(?ms)^  deployment-gate:\r?\n(?<body>.*?)(?=^  [A-Za-z0-9_-]+:\s*\r?$|\z)");
        if (deploymentGate.Success)
        {
            Assert.DoesNotContain("id-token: write", deploymentGate.Groups["body"].Value, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("actions: read", deploymentGate.Groups["body"].Value, StringComparison.OrdinalIgnoreCase);
        }
    }

    private static string FindRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var workflow = Path.Combine(directory.FullName, ".github", "workflows", "publish-image.yml");
            if (File.Exists(workflow))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("The publish workflow root was not found.");
    }
}
