using Legacy.Maliev.AuthService.Application;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Registers secure legacy identity and refresh-session infrastructure.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>Adds the unchanged identity readers and isolated PostgreSQL session store.</summary>
    public static IServiceCollection AddLegacyAuthInfrastructure(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // PostgreSQL is the migrated legacy store. SQL Server remains available only when
        // an operator explicitly selects it during the staged cutover window; silently
        // falling back to SQL Server would make a missing projection look healthy while
        // reading the wrong source of truth.
        var identityProvider = configuration["IdentityStorage:Provider"] ?? "PostgreSql";
        if (string.Equals(identityProvider, "PostgreSql", StringComparison.OrdinalIgnoreCase))
        {
            services.AddDbContext<CustomerIdentityDbContext>(options =>
                ConfigurePostgres(options, configuration, "CustomerIdentity"));
            services.AddDbContext<EmployeeIdentityDbContext>(options =>
                ConfigurePostgres(options, configuration, "EmployeeIdentity"));
        }
        else if (string.Equals(identityProvider, "SqlServer", StringComparison.OrdinalIgnoreCase))
        {
            services.AddDbContext<CustomerIdentityDbContext>(options =>
                ConfigureSqlServer(options, configuration, "CustomerIdentity"));
            services.AddDbContext<EmployeeIdentityDbContext>(options =>
                ConfigureSqlServer(options, configuration, "EmployeeIdentity"));
        }
        else
        {
            throw new InvalidOperationException(
                "IdentityStorage:Provider must be either 'SqlServer' or 'PostgreSql'.");
        }

        services.AddDbContext<RefreshSessionDbContext>(options =>
            ConfigurePostgres(options, configuration, "RefreshSessions"));

        services.AddScoped<IPasswordHasher<LegacyIdentityRow>, PasswordHasher<LegacyIdentityRow>>();
        services.AddScoped<LegacyIdentityReader>();
        services.AddScoped<ILegacyCredentialValidator>(provider => provider.GetRequiredService<LegacyIdentityReader>());
        services.AddScoped<ILegacyIdentityReader>(provider => provider.GetRequiredService<LegacyIdentityReader>());
        services.AddScoped<IGoogleEmployeeIdentityReader>(provider => provider.GetRequiredService<LegacyIdentityReader>());
        services.AddScoped<IRefreshSessionStore, PostgresRefreshSessionStore>();
        services.AddScoped<IGoogleIdentityNonceService, GoogleIdentityNonceService>();
        services.AddScoped<IGoogleIdentityTokenVerifier, GoogleIdentityTokenVerifier>();
        services.AddScoped<IGoogleIdentityTokenValidator, GoogleIdentityTokenValidator>();
        services.AddScoped<ICustomerIdentityAdminService, CustomerIdentityAdminService>();
        services.AddScoped<IEmployeeIdentityAdminService, EmployeeIdentityAdminService>();
        services.AddSingleton<IAccessTokenIssuer, RsaAccessTokenIssuer>();
        services.AddSingleton<IServiceAccessTokenIssuer>(provider => (RsaAccessTokenIssuer)provider.GetRequiredService<IAccessTokenIssuer>());
        services.AddSingleton(TimeProvider.System);
        services.AddScoped<AuthenticationService>();
        services.AddScoped<GoogleAuthenticationService>();
        services.AddScoped<ServiceAuthenticationService>();
        services.AddScoped<CustomerSelfService>();
        services.AddScoped<ICustomerLoginActionLifecycle>(provider => provider.GetRequiredService<CustomerSelfService>());
        services.AddScoped<EmployeeSelfService>();

        services.AddOptions<JwtOptions>()
            .Bind(configuration.GetSection(JwtOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();
        services.AddSingleton<IValidateOptions<ServiceClientOptions>, ServiceClientOptionsValidator>();
        services.AddOptions<ServiceClientOptions>()
            .Bind(configuration.GetSection(ServiceClientOptions.SectionName))
            .ValidateOnStart();

        return services;
    }

    private static void ConfigurePostgres(
        DbContextOptionsBuilder options,
        IConfiguration configuration,
        string connectionName)
    {
        var connectionString = EnsurePostgresConnectionPooling(
            configuration.GetConnectionString(connectionName),
            connectionName);

        options.UseNpgsql(connectionString, npgsqlOptions =>
        {
            npgsqlOptions.EnableRetryOnFailure(
                maxRetryCount: 5,
                maxRetryDelay: TimeSpan.FromSeconds(10),
                errorCodesToAdd: null);
            npgsqlOptions.CommandTimeout(120);
        });
    }

    private static void ConfigureSqlServer(
        DbContextOptionsBuilder options,
        IConfiguration configuration,
        string connectionName)
    {
        var connectionString = RequireConnection(configuration.GetConnectionString(connectionName), connectionName);
        options.UseSqlServer(connectionString, sqlServerOptions =>
        {
            sqlServerOptions.EnableRetryOnFailure(
                maxRetryCount: 5,
                maxRetryDelay: TimeSpan.FromSeconds(10),
                errorNumbersToAdd: null);
            sqlServerOptions.CommandTimeout(120);
        });
    }

    private static string EnsurePostgresConnectionPooling(string? connectionString, string connectionName)
    {
        var builder = new Npgsql.NpgsqlConnectionStringBuilder(RequireConnection(connectionString, connectionName));

        if (builder.MaxPoolSize == 100)
        {
            builder.MaxPoolSize = 20;
        }

        if (builder.MinPoolSize == 0)
        {
            builder.MinPoolSize = 2;
        }

        if (builder.ConnectionIdleLifetime == 300)
        {
            builder.ConnectionIdleLifetime = 60;
        }

        return builder.ConnectionString;
    }

    private static string RequireConnection(string? connectionString, string connectionName) =>
        string.IsNullOrWhiteSpace(connectionString)
            ? throw new InvalidOperationException($"ConnectionStrings:{connectionName} is required.")
            : connectionString;
}
