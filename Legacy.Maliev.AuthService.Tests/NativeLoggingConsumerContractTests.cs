using System.Text.Json;
using Maliev.Aspire.ServiceDefaults;
using Maliev.Aspire.ServiceDefaults.Middleware;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class NativeLoggingConsumerContractTests
{
    private const string SharedLoggingCommit = "d22f0e6f95254b10cf4fe891c8dce5df7c419f3f";

    [Fact]
    public void AuthHostAndDelivery_ConsumePinnedSharedLoggingWithoutNativeLogging()
    {
        var root = FindRepositoryRoot();
        var program = File.ReadAllText(Path.Combine(root, "Legacy.Maliev.AuthService.Api", "Program.cs"));
        var project = File.ReadAllText(Path.Combine(root, "Legacy.Maliev.AuthService.Api", "Legacy.Maliev.AuthService.Api.csproj"));
        var dockerfile = File.ReadAllText(Path.Combine(root, "Legacy.Maliev.AuthService.Api", "Dockerfile"));
        var workflow = File.ReadAllText(Path.Combine(root, ".github", "workflows", "_build-and-test.yml"));

        Assert.Contains("builder.AddServiceDefaults();", program, StringComparison.Ordinal);
        Assert.Contains("app.UseStandardMiddleware();", program, StringComparison.Ordinal);
        Assert.Contains("builder.AddStandardMiddleware();", program, StringComparison.Ordinal);
        Assert.DoesNotContain("EnableRequestLogging = true", program, StringComparison.Ordinal);
        Assert.False(new MiddlewareOptions().EnableRequestLogging);
        Assert.DoesNotContain("Maliev.NativeLogging", program, StringComparison.Ordinal);
        Assert.DoesNotContain("Maliev.NativeLogging", project, StringComparison.Ordinal);
        Assert.DoesNotContain("Maliev.NativeLogging", dockerfile, StringComparison.Ordinal);
        Assert.Contains($"ref: {SharedLoggingCommit}", workflow, StringComparison.Ordinal);
        Assert.Contains($"checkout {SharedLoggingCommit}", dockerfile, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false, 500, LogLevel.Critical, "/auth/v1/login")]
    [InlineData(true, 404, LogLevel.Debug, "/")]
    public async Task SharedProductionExceptionBoundary_RedactsAuthSecrets(
        bool notFound,
        int expectedStatus,
        LogLevel expectedLevel,
        string expectedLoggedPath)
    {
        var logger = new CaptureLogger();
        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();
        context.TraceIdentifier = "auth-correlation";
        context.Request.Method = "POST";
        context.Request.Path = notFound
            ? "/auth/v1/customer-identities/private-email@example.test"
            : "/auth/v1/login";
        context.Request.QueryString = new QueryString("?token=private-query");
        context.Request.Headers.Authorization = "Bearer private-header";
        var failure = notFound
            ? (Exception)new KeyNotFoundException("private-message")
            : new Exception("private-message");
        var middleware = new ExceptionHandlingMiddleware(_ => throw failure, logger, new ProductionEnvironment());

        await middleware.InvokeAsync(context);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(expectedLevel, entry.Level);
        Assert.Null(entry.Exception);
        Assert.Equal("UnhandledRequestFailure", entry.Values["EventName"]);
        Assert.Equal(expectedLoggedPath, entry.Values["Path"]);
        Assert.Equal(expectedStatus, entry.Values["StatusCode"]);
        Assert.Equal(context.TraceIdentifier, entry.Values["IncidentId"]);
        Assert.DoesNotContain("private-", entry.Message, StringComparison.Ordinal);
        Assert.Equal(expectedStatus, context.Response.StatusCode);
        context.Response.Body.Position = 0;
        using var json = await JsonDocument.ParseAsync(context.Response.Body);
        Assert.Equal(expectedStatus, json.RootElement.GetProperty("statusCode").GetInt32());
        Assert.Equal(context.TraceIdentifier, json.RootElement.GetProperty("traceId").GetString());
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("details").ValueKind);
        Assert.DoesNotContain("private-", json.RootElement.ToString(), StringComparison.Ordinal);
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

    private sealed class CaptureLogger : ILogger<ExceptionHandlingMiddleware>
    {
        public List<Entry> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add(new Entry(logLevel, exception, formatter(state, exception),
                ((IEnumerable<KeyValuePair<string, object?>>)state!).Where(pair => pair.Key != "{OriginalFormat}").ToDictionary()));
    }

    private sealed record Entry(LogLevel Level, Exception? Exception, string Message, Dictionary<string, object?> Values);

    private sealed class ProductionEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Production;

        public string ApplicationName { get; set; } = "Legacy.Maliev.AuthService.Api";

        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;

        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
