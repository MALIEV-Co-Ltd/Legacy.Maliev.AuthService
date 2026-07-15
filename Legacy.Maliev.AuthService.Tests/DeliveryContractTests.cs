namespace Legacy.Maliev.AuthService.Tests;

public sealed class DeliveryContractTests
{
    [Fact]
    public void DockerContext_ExcludesBuildAndRepositoryArtifacts()
    {
        var dockerIgnore = File.ReadAllText(Path.Combine(FindRepositoryRoot(), ".dockerignore"));

        Assert.Contains(".git", dockerIgnore, StringComparison.Ordinal);
        Assert.Contains("**/bin", dockerIgnore, StringComparison.Ordinal);
        Assert.Contains("**/obj", dockerIgnore, StringComparison.Ordinal);
        Assert.Contains("**/TestResults", dockerIgnore, StringComparison.Ordinal);
    }

    [Fact]
    public void KubernetesResources_AreConfinedToLegacyNamespaceAndDoNotProvisionInfrastructure()
    {
        var root = FindRepositoryRoot();
        var manifests = Directory.GetFiles(Path.Combine(root, "deploy", "base"), "*.yaml");
        var combined = string.Join('\n', manifests.Select(File.ReadAllText));

        Assert.NotEmpty(manifests);
        Assert.DoesNotContain("kind: Cluster", combined, StringComparison.Ordinal);
        Assert.DoesNotContain("kind: NodePool", combined, StringComparison.Ordinal);
        Assert.DoesNotContain("CloudSQL", combined, StringComparison.OrdinalIgnoreCase);
        Assert.All(
            manifests.Where(path => !path.EndsWith("kustomization.yaml", StringComparison.Ordinal)),
            path => Assert.Contains("namespace: maliev-legacy", File.ReadAllText(path), StringComparison.Ordinal));
    }

    [Fact]
    public void Deployment_IsResourceBoundedNonRootAndUsesRuntimeSecretProjection()
    {
        var deployment = File.ReadAllText(
            Path.Combine(FindRepositoryRoot(), "deploy", "base", "deployment.yaml"));

        Assert.Contains("replicas: 1", deployment, StringComparison.Ordinal);
        Assert.Contains("runAsNonRoot: true", deployment, StringComparison.Ordinal);
        Assert.Contains("readOnlyRootFilesystem: true", deployment, StringComparison.Ordinal);
        Assert.Contains("drop: [\"ALL\"]", deployment, StringComparison.Ordinal);
        Assert.Contains("name: legacy-maliev-auth-runtime", deployment, StringComparison.Ordinal);
        Assert.Contains("requests:", deployment, StringComparison.Ordinal);
        Assert.Contains("limits:", deployment, StringComparison.Ordinal);
    }

    [Fact]
    public void PublishWorkflow_IsProtectedByExplicitCostAndMigrationGate()
    {
        var workflow = File.ReadAllText(
            Path.Combine(FindRepositoryRoot(), ".github", "workflows", "publish-image.yml"));

        Assert.Contains("vars.LEGACY_DEPLOY_ENABLED == 'true'", workflow, StringComparison.Ordinal);
        Assert.Contains("Legacy.Maliev.Workflows/.github/workflows/publish-image.yml@6017816", workflow, StringComparison.Ordinal);
        Assert.Contains("legacy-production", workflow, StringComparison.Ordinal);
        Assert.DoesNotContain("kubectl apply", workflow, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Dockerfile_UsesDotNet10AndRunsAsNonRoot()
    {
        var dockerfile = File.ReadAllText(
            Path.Combine(FindRepositoryRoot(), "Legacy.Maliev.AuthService.Api", "Dockerfile"));

        Assert.Contains("dotnet/sdk:10.0-alpine", dockerfile, StringComparison.Ordinal);
        Assert.Contains("dotnet/aspnet:10.0-alpine", dockerfile, StringComparison.Ordinal);
        Assert.Contains("USER $APP_UID", dockerfile, StringComparison.Ordinal);
        Assert.Contains("checkout 085f24b8b6b19c5a8e932b229d93421b03bcd032", dockerfile, StringComparison.Ordinal);
        Assert.Contains("checkout c533c12a8154f5cf7c4fbc9734e82a62705ac60f", dockerfile, StringComparison.Ordinal);

        var migrationDockerfile = File.ReadAllText(
            Path.Combine(FindRepositoryRoot(), "Legacy.Maliev.AuthService.IdentityMigration", "Dockerfile"));
        Assert.Contains("dotnet/sdk:10.0-alpine", migrationDockerfile, StringComparison.Ordinal);
        Assert.Contains("dotnet/runtime:10.0-alpine", migrationDockerfile, StringComparison.Ordinal);
        Assert.Contains("USER $APP_UID", migrationDockerfile, StringComparison.Ordinal);
    }

    [Fact]
    public void IdentityMigrationImage_IsProtectedBySameDeploymentGate()
    {
        var workflow = File.ReadAllText(
            Path.Combine(FindRepositoryRoot(), ".github", "workflows", "publish-identity-migration.yml"));

        Assert.Contains("vars.LEGACY_DEPLOY_ENABLED == 'true'", workflow, StringComparison.Ordinal);
        Assert.Contains("legacy-maliev-auth-identity-migration", workflow, StringComparison.Ordinal);
        Assert.DoesNotContain("kubectl apply", workflow, StringComparison.OrdinalIgnoreCase);
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Legacy.Maliev.AuthService.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new DirectoryNotFoundException("Repository root was not found.");
    }
}
