var builder = WebApplication.CreateBuilder(args);
builder.Services.AddProblemDetails();

var app = builder.Build();
app.UseExceptionHandler();
app.MapGet("/auth/liveness", () => Results.Ok(new { status = "Healthy" }));
app.MapGet("/auth/readiness", () => Results.Ok(new { status = "Healthy" }));
await app.RunAsync();

/// <summary>Legacy Auth Service entry point.</summary>
public partial class Program;