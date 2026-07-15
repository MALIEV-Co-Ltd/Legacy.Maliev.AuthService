using Legacy.Maliev.AuthService.Application;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Registers secure legacy identity and refresh-session infrastructure.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>Adds the unchanged identity readers and isolated PostgreSQL session store.</summary>
    public static IServiceCollection AddLegacyAuthInfrastructure(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        var identityProvider = configuration["IdentityStorage:Provider"] ?? "SqlServer";
        if (string.Equals(identityProvider, "PostgreSql", StringComparison.OrdinalIgnoreCase))
        {
            services.AddDbContext<CustomerIdentityDbContext>(options =>
                options.UseNpgsql(configuration.GetConnectionString("CustomerIdentity")));
            services.AddDbContext<EmployeeIdentityDbContext>(options =>
                options.UseNpgsql(configuration.GetConnectionString("EmployeeIdentity")));
        }
        else if (string.Equals(identityProvider, "SqlServer", StringComparison.OrdinalIgnoreCase))
        {
            services.AddDbContext<CustomerIdentityDbContext>(options =>
                options.UseSqlServer(configuration.GetConnectionString("CustomerIdentity")));
            services.AddDbContext<EmployeeIdentityDbContext>(options =>
                options.UseSqlServer(configuration.GetConnectionString("EmployeeIdentity")));
        }
        else
        {
            throw new InvalidOperationException(
                "IdentityStorage:Provider must be either 'SqlServer' or 'PostgreSql'.");
        }

        services.AddDbContext<RefreshSessionDbContext>(options =>
            options.UseNpgsql(configuration.GetConnectionString("RefreshSessions")));

        services.AddScoped<IPasswordHasher<LegacyIdentityRow>, PasswordHasher<LegacyIdentityRow>>();
        services.AddScoped<LegacyIdentityReader>();
        services.AddScoped<ILegacyCredentialValidator>(provider => provider.GetRequiredService<LegacyIdentityReader>());
        services.AddScoped<ILegacyIdentityReader>(provider => provider.GetRequiredService<LegacyIdentityReader>());
        services.AddScoped<IRefreshSessionStore, PostgresRefreshSessionStore>();
        services.AddScoped<ICustomerIdentityAdminService, CustomerIdentityAdminService>();
        services.AddScoped<IEmployeeIdentityAdminService, EmployeeIdentityAdminService>();
        services.AddSingleton<IAccessTokenIssuer, RsaAccessTokenIssuer>();
        services.AddSingleton<IServiceAccessTokenIssuer>(provider => (RsaAccessTokenIssuer)provider.GetRequiredService<IAccessTokenIssuer>());
        services.AddSingleton(TimeProvider.System);
        services.AddScoped<AuthenticationService>();
        services.AddScoped<ServiceAuthenticationService>();
        services.AddScoped<CustomerSelfService>();

        services.AddOptions<JwtOptions>()
            .Bind(configuration.GetSection(JwtOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();
        services.AddOptions<ServiceClientOptions>()
            .Bind(configuration.GetSection(ServiceClientOptions.SectionName));

        return services;
    }
}
