using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class IdentityStorageConfigurationTests
{
    [Theory]
    [InlineData(null, "Microsoft.EntityFrameworkCore.SqlServer")]
    [InlineData("SqlServer", "Microsoft.EntityFrameworkCore.SqlServer")]
    [InlineData("PostgreSql", "Npgsql.EntityFrameworkCore.PostgreSQL")]
    public void AddInfrastructure_SelectsTheConfiguredIdentityProvider(
        string? provider,
        string expectedProvider)
    {
        var settings = new Dictionary<string, string?>
        {
            ["ConnectionStrings:CustomerIdentity"] = ProviderConnection(provider),
            ["ConnectionStrings:EmployeeIdentity"] = ProviderConnection(provider),
            ["ConnectionStrings:RefreshSessions"] = "Host=localhost;Database=auth",
            ["IdentityStorage:Provider"] = provider,
            ["Jwt:Issuer"] = "https://test.invalid",
            ["Jwt:Audience"] = "test",
            ["Jwt:PrivateKeyPem"] = "test-only",
            ["Jwt:KeyId"] = "test",
        };
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        var services = new ServiceCollection();

        services.AddLegacyAuthInfrastructure(configuration);

        using var providerServices = services.BuildServiceProvider();
        using var customer = providerServices.GetRequiredService<CustomerIdentityDbContext>();
        using var employee = providerServices.GetRequiredService<EmployeeIdentityDbContext>();
        Assert.Equal(expectedProvider, customer.Database.ProviderName);
        Assert.Equal(expectedProvider, employee.Database.ProviderName);
    }

    private static string ProviderConnection(string? provider) =>
        string.Equals(provider, "PostgreSql", StringComparison.OrdinalIgnoreCase)
            ? "Host=localhost;Database=identity"
            : "Server=localhost;Database=identity;Integrated Security=true;TrustServerCertificate=true";
}
