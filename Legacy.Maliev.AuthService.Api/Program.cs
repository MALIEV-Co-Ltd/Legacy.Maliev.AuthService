using Legacy.Maliev.AuthService.Infrastructure;
using Maliev.Aspire.ServiceDefaults;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();
builder.AddDefaultApiVersioning();
builder.AddStandardCors();
builder.AddStandardMiddleware(options => options.EnableRequestLogging = true);
builder.AddStandardOpenApi(
    title: "Legacy MALIEV Auth Service API",
    description: "Secure temporary authentication boundary for unchanged legacy customer and employee identities.");

builder.Services.AddProblemDetails();
builder.Services.AddControllers();
builder.Services.AddLegacyAuthInfrastructure(builder.Configuration);
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
});
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("login", context => RateLimitPartition.GetFixedWindowLimiter(
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

/// <summary>Legacy Auth Service entry point.</summary>
public partial class Program;
