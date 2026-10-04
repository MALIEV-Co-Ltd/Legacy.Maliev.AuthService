using Legacy.Maliev.AuthService.Api.Controllers;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using System.Reflection;
using System.Text.Json;
using System.Xml.Linq;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class OpenApiHttpContractTests : IClassFixture<CustomerIdentityAuthorizationTests.AuthApiFactory>
{
    private readonly CustomerIdentityAuthorizationTests.AuthApiFactory factory;

    public OpenApiHttpContractTests(CustomerIdentityAuthorizationTests.AuthApiFactory factory) => this.factory = factory;

    [Fact]
    public async Task Document_PreservesAuthXmlSummariesAndPublicResponseContracts()
    {
        using var client = CreateClient(factory);
        using var response = await client.GetAsync("/auth/openapi/v1.json");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("Legacy MALIEV Auth Service API", document.RootElement.GetProperty("info").GetProperty("title").GetString());

        var paths = document.RootElement.GetProperty("paths");
        var login = paths.GetProperty("/auth/v1/login").GetProperty("post");
        var serviceLogin = paths.GetProperty("/auth/v1/service/login").GetProperty("post");
        Assert.True(login.TryGetProperty("summary", out var loginSummary), "Served OpenAPI login summary is missing.");
        Assert.True(serviceLogin.TryGetProperty("summary", out var serviceSummary), "Served OpenAPI service-login summary is missing.");
        Assert.Equal(XmlSummary(nameof(AuthenticationController.Login)), loginSummary.GetString());
        Assert.Equal(XmlSummary(nameof(AuthenticationController.ServiceLogin)), serviceSummary.GetString());
        foreach (var status in new[] { "200", "401", "409", "429" })
            Assert.True(login.GetProperty("responses").TryGetProperty(status, out _), $"Login documentation omits HTTP {status}.");
        foreach (var status in new[] { "200", "401" })
            Assert.True(serviceLogin.GetProperty("responses").TryGetProperty(status, out _), $"Service login documentation omits HTTP {status}.");
    }

    [Fact]
    public async Task Document_DescribesJsonCredentialAndTokenEnvelopeWithoutRuntimeSecrets()
    {
        using var client = CreateClient(factory);
        using var response = await client.GetAsync("/auth/openapi/v1.json");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        var operation = root.GetProperty("paths").GetProperty("/auth/v1/login").GetProperty("post");
        var request = ResolveSchema(root, operation.GetProperty("requestBody").GetProperty("content")
            .GetProperty("application/json").GetProperty("schema"));
        Assert.Equal(new[] { "identityKind", "password", "userName" }, PropertyNames(request));
        var required = request.GetProperty("required").EnumerateArray().Select(value => value.GetString()).ToArray();
        Assert.Contains("userName", required);
        Assert.Contains("password", required);

        var token = ResolveSchema(root, operation.GetProperty("responses").GetProperty("200").GetProperty("content")
            .GetProperty("application/json").GetProperty("schema"));
        Assert.Equal(new[] { "accessToken", "expiresIn", "refreshExpiresAt", "refreshToken", "tokenType" }, PropertyNames(token));
        Assert.DoesNotContain("PRIVATE KEY", json, StringComparison.Ordinal);
        Assert.DoesNotContain("ConnectionStrings", json, StringComparison.Ordinal);
        Assert.DoesNotContain("Host=localhost", json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Production_DoesNotPublishDocumentationRoute()
    {
        using var production = factory.WithWebHostBuilder(builder => builder.UseEnvironment("Production"));
        using var client = CreateClient(production);
        using var response = await client.GetAsync("/auth/openapi/v1.json");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    private static HttpClient CreateClient(WebApplicationFactory<Program> app) => app.CreateClient(
        new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });

    private static string XmlSummary(string methodName)
    {
        var method = typeof(AuthenticationController).GetMethod(methodName, BindingFlags.Public | BindingFlags.Instance)
            ?? throw new InvalidOperationException("Documented controller method is missing.");
        var parameters = string.Join(',', method.GetParameters().Select(parameter => parameter.ParameterType.FullName));
        var memberName = $"M:{typeof(AuthenticationController).FullName}.{methodName}({parameters})";
        var xml = XDocument.Load(Path.ChangeExtension(typeof(Program).Assembly.Location, ".xml"));
        var summary = xml.Descendants("member").Single(member => (string?)member.Attribute("name") == memberName)
            .Element("summary")?.Value ?? throw new InvalidOperationException("Compiled Auth XML summary is missing.");
        return string.Join(' ', summary.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
    }

    private static JsonElement ResolveSchema(JsonElement root, JsonElement schema)
    {
        if (!schema.TryGetProperty("$ref", out var reference)) return schema;
        var path = reference.GetString() ?? throw new InvalidOperationException("Schema reference is empty.");
        const string prefix = "#/components/schemas/";
        Assert.True(path.StartsWith(prefix, StringComparison.Ordinal), "Schema reference is not a local component reference.");
        return root.GetProperty("components").GetProperty("schemas").GetProperty(path[prefix.Length..]);
    }

    private static string[] PropertyNames(JsonElement schema) => schema.GetProperty("properties")
        .EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal).ToArray();
}
