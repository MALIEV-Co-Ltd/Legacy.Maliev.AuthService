using Legacy.Maliev.AuthService.Infrastructure;
using Legacy.Maliev.AuthService.Api.Authorization;
using Legacy.Maliev.AuthService.Api.Security;
using Maliev.Aspire.ServiceDefaults;
using Maliev.Aspire.ServiceDefaults.Diagnostics;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using System.Threading.RateLimiting;

await PrivateStartupBoundary.RunAsync(async () =>
{
    var builder = WebApplication.CreateBuilder(args);

    builder.AddServiceDefaults();
    builder.AddDefaultApiVersioning();
    builder.AddStandardCors();
    // RequestLoggingMiddleware emits raw URL paths, which can contain auth secrets.
    // Keep the shared correlated exception boundary without that optional request log.
    builder.AddStandardMiddleware();
    builder.AddStandardOpenApi(
        title: "Legacy MALIEV Auth Service API",
        description: "Secure temporary authentication boundary for unchanged legacy customer and employee identities.");
    // The built-in registration activates this assembly's generated XML comment transformers.
    builder.Services.AddOpenApi("v1");

    builder.Services.AddProblemDetails();
    builder.Services.AddControllers();
    builder.Services.AddSingleton<LoginAttemptRateLimiter>();
    builder.Services.AddSingleton<LoginRateLimitFilter>();
    builder.Services.AddScoped<QualificationIntrospectionBoundaryFilter>();
    builder.Services.AddSingleton<QualificationIntrospectionRateLimiter>();
    builder.Services.AddLegacyAuthInfrastructure(builder.Configuration);
    builder.AddQuotationInvoiceLiveAuthority();
    // Auth readiness must reflect every PostgreSQL store used by the service. The
    // infrastructure registrations above are intentionally explicit, so register
    // their health checks here rather than relying on the shared helper.
    builder.Services.AddHealthChecks()
        .AddDbContextCheck<CustomerIdentityDbContext>("auth_customer_identity", tags: ["db", "ready"])
        .AddDbContextCheck<EmployeeIdentityDbContext>("auth_employee_identity", tags: ["db", "ready"])
        .AddDbContextCheck<RefreshSessionDbContext>("auth_refresh_sessions", tags: ["db", "ready"]);
    builder.Services.AddHealthChecks().AddCheck<EmployeeRecoveryHealthCheck>("auth_employee_recovery_schema", tags: ["db", "ready"]);
    builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();
    builder.Services.AddSingleton<IConfigureOptions<Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerOptions>, LegacyJwtBearerConfiguration>();
    builder.Services.AddAuthorizationBuilder().AddPolicy("LegacyEmployee", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireClaim("identity_kind", "employee");
    }).AddPolicy("LegacyCustomer", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireClaim("identity_kind", "customer");
    }).AddPolicy("LegacyService", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireClaim("identity_kind", "service");
    });
    builder.Services.AddPermissionAuthorization();
    builder.Services.AddRateLimiter(options =>
    {
        options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
        options.AddPolicy("service-login", context => RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 30,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true,
            }));
        options.AddPolicy("login", context => RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true,
            }));
        options.AddPolicy("revoke", context => RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true,
            }));
        options.AddPolicy("credential-change", context => RateLimitPartition.GetFixedWindowLimiter(
            context.User.FindFirst("sub")?.Value
                ?? context.Connection.RemoteIpAddress?.ToString()
                ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(5),
                QueueLimit = 0,
                AutoReplenishment = true,
            }));
    });

    var app = builder.Build();

    app.UseStandardMiddleware();
    app.UseCors();
    app.UseRateLimiter();
    app.UseAuthentication();
    app.UseAuthorization();
    app.MapDefaultEndpoints("auth");
    app.MapControllers();
    app.MapApiDocumentation(servicePrefix: "auth");

    await app.RunAsync();

});

/// <summary>Legacy Auth Service entry point.</summary>
public partial class Program;
