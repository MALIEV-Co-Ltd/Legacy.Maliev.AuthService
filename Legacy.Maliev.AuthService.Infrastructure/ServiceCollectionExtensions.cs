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
        services.AddDbContext<CustomerIdentityDbContext>(options =>
            options.UseSqlServer(configuration.GetConnectionString("CustomerIdentity")));
        services.AddDbContext<EmployeeIdentityDbContext>(options =>
            options.UseSqlServer(configuration.GetConnectionString("EmployeeIdentity")));
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
        services.AddSingleton(TimeProvider.System);
        services.AddScoped<AuthenticationService>();

        services.AddOptions<JwtOptions>()
            .Bind(configuration.GetSection(JwtOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        return services;
    }
}
