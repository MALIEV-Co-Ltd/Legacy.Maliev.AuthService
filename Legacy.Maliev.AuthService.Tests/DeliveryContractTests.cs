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
    public void NetworkPolicy_AllowsOnlyHttpsForGoogleIdentityCertificateRefresh()
    {
        var policy = File.ReadAllText(
            Path.Combine(FindRepositoryRoot(), "deploy", "base", "network-policy.yaml"));

        Assert.Contains("cidr: 0.0.0.0/0", policy, StringComparison.Ordinal);
        Assert.Contains("- protocol: TCP\n          port: 443", policy, StringComparison.Ordinal);
    }

    [Fact]
    public void Readiness_ProbesEveryAuthPostgresStore()
    {
        var program = File.ReadAllText(
            Path.Combine(FindRepositoryRoot(), "Legacy.Maliev.AuthService.Api", "Program.cs"));

        Assert.Contains(
            ".AddDbContextCheck<CustomerIdentityDbContext>(\"auth_customer_identity\", tags: [\"db\", \"ready\"])",
            program,
            StringComparison.Ordinal);
        Assert.Contains(
            ".AddDbContextCheck<EmployeeIdentityDbContext>(\"auth_employee_identity\", tags: [\"db\", \"ready\"])",
            program,
            StringComparison.Ordinal);
        Assert.Contains(
            ".AddDbContextCheck<RefreshSessionDbContext>(\"auth_refresh_sessions\", tags: [\"db\", \"ready\"])",
            program,
            StringComparison.Ordinal);
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
        Assert.Contains("checkout 1a7e4ba3c3dfd8c8793e9ad7da2083dc4df6cf4f", dockerfile, StringComparison.Ordinal);
        Assert.Contains("checkout 78e48ffc4ee000df0510cba5e7c7a3c4c4d539d7", dockerfile, StringComparison.Ordinal);

    }

    [Fact]
    public void SharedDependencies_UseOnlyPublicLegacyRepositoryAndPackageIdentities()
    {
        var root = FindRepositoryRoot();
        var apiProject = File.ReadAllText(Path.Combine(
            root,
            "Legacy.Maliev.AuthService.Api",
            "Legacy.Maliev.AuthService.Api.csproj"));
        var workflow = File.ReadAllText(Path.Combine(root, ".github", "workflows", "_build-and-test.yml"));
        var dockerfile = File.ReadAllText(Path.Combine(root, "Legacy.Maliev.AuthService.Api", "Dockerfile"));
        var combined = string.Join('\n', apiProject, workflow, dockerfile);

        Assert.Contains("Legacy.Maliev.ServiceDefaults", apiProject, StringComparison.Ordinal);
        Assert.Contains("MALIEV-Co-Ltd/Legacy.Maliev.ServiceDefaults", workflow, StringComparison.Ordinal);
        Assert.Contains("ref: 1a7e4ba3c3dfd8c8793e9ad7da2083dc4df6cf4f", workflow, StringComparison.Ordinal);
        Assert.Contains("MALIEV-Co-Ltd/Legacy.Maliev.CompatibilityContracts", workflow, StringComparison.Ordinal);
        Assert.Contains("MALIEV-Co-Ltd/Legacy.Maliev.ServiceDefaults.git", dockerfile, StringComparison.Ordinal);
        Assert.Contains("MALIEV-Co-Ltd/Legacy.Maliev.CompatibilityContracts.git", dockerfile, StringComparison.Ordinal);
        Assert.DoesNotContain("MALIEV-Co-Ltd/Maliev.Aspire", combined, StringComparison.Ordinal);
        Assert.DoesNotContain("MALIEV-Co-Ltd/Maliev.MessagingContracts", combined, StringComparison.Ordinal);
        Assert.DoesNotContain("Include=\"Maliev.Aspire.ServiceDefaults\"", apiProject, StringComparison.Ordinal);
    }

    [Fact]
    public void TestProject_IsDiscoverableAndPublishesXplatCoverage()
    {
        var testProject = File.ReadAllText(
            Path.Combine(FindRepositoryRoot(), "Legacy.Maliev.AuthService.Tests", "Legacy.Maliev.AuthService.Tests.csproj"));

        Assert.Contains("<IsTestProject>true</IsTestProject>", testProject, StringComparison.Ordinal);
        Assert.Contains("<PackageReference Include=\"coverlet.collector\" Version=\"6.0.4\" />", testProject, StringComparison.Ordinal);
    }

    [Fact]
    public void DeploymentContract_ListsTheExactLegacyWebServicePermissions()
    {
        var deploymentContract = File.ReadAllText(
            Path.Combine(FindRepositoryRoot(), "deploy", "README.md"));
        var permissionParagraph = System.Text.RegularExpressions.Regex.Match(
            deploymentContract,
            "numbered permission entries for only (?<permissions>.+?)\\. Web receives",
            System.Text.RegularExpressions.RegexOptions.Singleline);
        Assert.True(permissionParagraph.Success, "The legacy-web permission contract paragraph was not found.");

        var permissions = System.Text.RegularExpressions.Regex.Matches(
                permissionParagraph.Groups["permissions"].Value,
                "`([^`]+)`")
            .Select(match => match.Groups[1].Value)
            .ToArray();

        Assert.Equal(
            [
                "legacy-auth.customer-self-service",
                "legacy-customer.customers.create",
                "legacy-customer.customers.delete",
                "legacy-customer.customers.read",
                "legacy-customer.customers.update",
                "legacy-customer.addresses.create",
                "legacy-customer.addresses.update",
                "legacy-customer.companies.create",
                "legacy-customer.companies.update",
                "legacy-customer.companies.delete",
                "legacy.customer-orders.read",
                "legacy.customer-orders.cancel",
                "legacy.customer-quotations.read",
                "legacy-contact.messages.create",
                "legacy.quotation-requests.create",
                "legacy.quotation-files.write",
                "legacy-file.uploads.create",
                "legacy-file.uploads.delete",
                "legacy.notifications.send",
            ],
            permissions);
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
