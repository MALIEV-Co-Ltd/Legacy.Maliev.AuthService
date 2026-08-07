using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Npgsql;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class IdentityStorageConfigurationTests
{
    [Fact]
    public void AddInfrastructure_UsesPostgreSqlForBothIdentityContexts()
    {
        var settings = new Dictionary<string, string?>
        {
            ["ConnectionStrings:CustomerIdentity"] = "Host=localhost;Database=identity",
            ["ConnectionStrings:EmployeeIdentity"] = "Host=localhost;Database=identity",
            ["ConnectionStrings:RefreshSessions"] = "Host=localhost;Database=auth",
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
        Assert.Equal("Npgsql.EntityFrameworkCore.PostgreSQL", customer.Database.ProviderName);
        Assert.Equal("Npgsql.EntityFrameworkCore.PostgreSQL", employee.Database.ProviderName);
        Assert.True(customer.Database.CreateExecutionStrategy().RetriesOnFailure);
        Assert.Equal(120, customer.Database.GetCommandTimeout());
        Assert.True(employee.Database.CreateExecutionStrategy().RetriesOnFailure);
        Assert.Equal(120, employee.Database.GetCommandTimeout());

        var connection = new NpgsqlConnectionStringBuilder(customer.Database.GetDbConnection().ConnectionString);
        Assert.Equal(20, connection.MaxPoolSize);
        Assert.Equal(2, connection.MinPoolSize);
        Assert.Equal(60, connection.ConnectionIdleLifetime);
    }
}
