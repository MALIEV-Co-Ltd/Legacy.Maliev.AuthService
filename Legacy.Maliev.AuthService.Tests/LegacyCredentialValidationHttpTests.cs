using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Security.Cryptography;
using Legacy.Maliev.AuthService.Infrastructure;
using Legacy.Maliev.AuthService.Application;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class LegacyCredentialValidationHttpTests(PostgresFixture postgres)
{
    private const string Password = "source-validation-test-password";

    [Theory]
    [InlineData("/customers/v1/validate", false)]
    [InlineData("/Employees/v1/validate", true)]
    public async Task Validation_OriginalInputAndOutcomeContractHasNoSession(string path, bool employee)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        using var unknownVersion = await client.PostAsJsonAsync(path.Replace("/v1/", "/v2/", StringComparison.Ordinal),
            new { Username = "source-user", Password });
        Assert.Equal(HttpStatusCode.NotFound, unknownVersion.StatusCode);
        foreach (var body in new[] { "", "null", " \t", "{}", "{\"Username\":\" \",\"Password\":\"value\"}", "{\"Username\":\"source-user\",\"Password\":\"\\t\"}" })
        {
            using var invalid = await client.PostAsync(path, new StringContent(body, System.Text.Encoding.UTF8, "application/json"));
            Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
            if (string.IsNullOrWhiteSpace(body) || body == "null")
            {
                Assert.Equal("application/problem+json", invalid.Content.Headers.ContentType?.MediaType);
                using var problem = JsonDocument.Parse(await invalid.Content.ReadAsStringAsync());
                Assert.Equal(400, problem.RootElement.GetProperty("status").GetInt32());
                Assert.True(problem.RootElement.TryGetProperty("errors", out _));
            }
            else
            {
                Assert.Equal("Username and password are required.", await invalid.Content.ReadAsStringAsync());
            }
        }

        using var missing = await client.PostAsJsonAsync(path, new { Username = "missing-user", Password });
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
        Assert.Equal("User not found.", await missing.Content.ReadAsStringAsync());
        var row = await stores.SeedAsync(employee, rehash: false);
        using var wrong = await client.PostAsJsonAsync(path, new { Username = "source-user", Password = "wrong" });
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        using var crossDomain = await client.PostAsJsonAsync(employee ? "/customers/v1/validate" : "/Employees/v1/validate",
            new { Username = "source-user", Password });
        Assert.Equal(HttpStatusCode.NotFound, crossDomain.StatusCode);
        using var success = await client.PostAsJsonAsync(path, new { Username = "SOURCE-USER", Password });
        await AssertEmptySuccessAsync(success);
        var requestType = typeof(ILegacyCredentialValidator).Assembly.GetType(
            "Legacy.Maliev.AuthService.Application.LegacyCredentialValidationRequest");
        Assert.NotNull(requestType);
        var representationProbe = Activator.CreateInstance(requestType)!;
        requestType.GetProperty("Username")!.SetValue(representationProbe, "private-username-sentinel");
        requestType.GetProperty("Password")!.SetValue(representationProbe, "private-password-sentinel");
        Assert.DoesNotContain("private-username-sentinel", representationProbe.ToString()!, StringComparison.Ordinal);
        Assert.DoesNotContain("private-password-sentinel", representationProbe.ToString()!, StringComparison.Ordinal);
        var after = await stores.ReadAsync(employee);
        Assert.Equal(row.PasswordHash, after.PasswordHash);
        Assert.Equal(row.SecurityStamp, after.SecurityStamp);
        Assert.Equal(row.ConcurrencyStamp, after.ConcurrencyStamp);
        Assert.Equal(row.NormalizedEmail, after.NormalizedEmail);
        AssertUnchangedEligibility(row, after);
        Assert.Equal(0, await stores.State.RefreshSessions.CountAsync());
        Assert.Equal(0, await stores.State.IdentityActionTokens.CountAsync());
        using var unchangedModernParser = await client.PostAsync("/auth/v1/login", new StringContent(
            "{'userName':'missing@validation.test','password':'invalid','identityKind':0}",
            System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, unchangedModernParser.StatusCode);
    }

    [Theory]
    [InlineData("/customers/v1/validate", false)]
    [InlineData("/Employees/v1/validate", true)]
    public async Task Validation_RehashPersistsHashStampsAndSourceNormalizationOnly(string path, bool employee)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var row = await stores.SeedAsync(employee, rehash: true);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        using var success = await client.PostAsJsonAsync(path, new { Username = "source-user", Password });
        await AssertEmptySuccessAsync(success);
        var after = await stores.ReadAsync(employee);
        Assert.NotEqual(row.PasswordHash, after.PasswordHash);
        Assert.Equal(PasswordVerificationResult.Success,
            new PasswordHasher<LegacyIdentityRow>().VerifyHashedPassword(after, after.PasswordHash!, Password));
        Assert.NotEqual(row.SecurityStamp, after.SecurityStamp);
        Assert.NotEqual(row.ConcurrencyStamp, after.ConcurrencyStamp);
        Assert.Equal("SOURCE-USER", after.NormalizedUserName);
        Assert.Equal("SOURCE@VALIDATION.TEST", after.NormalizedEmail);
        AssertUnchangedEligibility(row, after);
        Assert.Equal(0, await stores.State.RefreshSessions.CountAsync());
        Assert.Equal(0, await stores.State.IdentityActionTokens.CountAsync());
    }

    [Theory]
    [InlineData("/customers/v1/validate", false)]
    [InlineData("/Employees/v1/validate", true)]
    public async Task Validation_UserValidationFailureSuppressesRehashButNotVerifiedPassword(string path, bool employee)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var row = await stores.SeedAsync(employee, rehash: true, invalidEmail: true);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        using var success = await client.PostAsJsonAsync(path, new { Username = "source-user", Password });
        await AssertEmptySuccessAsync(success);
        var after = await stores.ReadAsync(employee);
        Assert.Equal(row.PasswordHash, after.PasswordHash);
        Assert.Equal(row.SecurityStamp, after.SecurityStamp);
        Assert.Equal(row.ConcurrencyStamp, after.ConcurrencyStamp);
        Assert.Equal(row.NormalizedEmail, after.NormalizedEmail);
        AssertUnchangedEligibility(row, after);
        Assert.Equal(0, await stores.State.RefreshSessions.CountAsync());
        Assert.Equal(0, await stores.State.IdentityActionTokens.CountAsync());
    }

    [Theory]
    [InlineData("/customers/v1/validate", false)]
    [InlineData("/Employees/v1/validate", true)]
    public async Task Validation_ConcurrentChangeIsNotOverwrittenAndVerifiedPasswordStillSucceeds(string path, bool employee)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var row = await stores.SeedAsync(employee, rehash: true);
        var replacement = new PasswordHasher<LegacyIdentityRow>().HashPassword(row, "replacement-test-password");
        var hasher = new ConcurrentHasher(() =>
        {
            var context = stores.Context(employee);
            Assert.Equal(1, context.Users.Where(user => user.Id == row.Id).ExecuteUpdate(update => update
                .SetProperty(user => user.PasswordHash, replacement)
                .SetProperty(user => user.SecurityStamp, "concurrent-security")
                .SetProperty(user => user.ConcurrencyStamp, "concurrent-version")));
        });
        await using var factory = new Factory(stores, hasher);
        using var client = factory.CreateClient();
        using var success = await client.PostAsJsonAsync(path, new { Username = "source-user", Password });
        await AssertEmptySuccessAsync(success);
        Assert.Equal(1, hasher.Interventions);
        var after = await stores.ReadAsync(employee);
        Assert.Equal(replacement, after.PasswordHash);
        Assert.Equal("concurrent-security", after.SecurityStamp);
        Assert.Equal("concurrent-version", after.ConcurrencyStamp);
        AssertUnchangedEligibility(row, after);
        Assert.Equal(0, await stores.State.RefreshSessions.CountAsync());
        Assert.Equal(0, await stores.State.IdentityActionTokens.CountAsync());
    }

    [Theory]
    [InlineData("/customers/v1/validate", false)]
    [InlineData("/Employees/v1/validate", true)]
    public async Task Validation_ActualRehashStoreExceptionIsNotReportedAsSuccess(string path, bool employee)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var row = await stores.SeedAsync(employee, rehash: true);
        await stores.Context(employee).Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION reject_validation_rehash() RETURNS trigger LANGUAGE plpgsql AS
            $$ BEGIN RAISE EXCEPTION 'controlled validation write failure'; END; $$;
            CREATE TRIGGER reject_validation_rehash BEFORE UPDATE ON "AspNetUsers"
            FOR EACH ROW EXECUTE FUNCTION reject_validation_rehash();
            """);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        using var response = await client.PostAsJsonAsync(path, new { Username = "source-user", Password });
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.False(response.Headers.Contains("Set-Cookie"));
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain(Password, body, StringComparison.Ordinal);
        Assert.DoesNotContain("controlled validation write failure", body, StringComparison.Ordinal);
        var after = await stores.ReadAsync(employee);
        Assert.Equal(row.PasswordHash, after.PasswordHash);
        Assert.Equal(row.SecurityStamp, after.SecurityStamp);
        Assert.Equal(row.ConcurrencyStamp, after.ConcurrencyStamp);
        AssertUnchangedEligibility(row, after);
        Assert.Equal(0, await stores.State.RefreshSessions.CountAsync());
        Assert.Equal(0, await stores.State.IdentityActionTokens.CountAsync());
    }

    [Theory]
    [InlineData("/customers/v1/validate", false, "123", "123", "12345", "12345")]
    [InlineData("/Employees/v1/validate", true, "123", "123", "12345", "12345")]
    [InlineData("/customers/v1/validate", false, "true", "true", "false", "false")]
    [InlineData("/Employees/v1/validate", true, "true", "true", "false", "false")]
    [InlineData("/customers/v1/validate", false, "-1.25e+2", "-1.25e+2", "1e-2", "1e-2")]
    [InlineData("/Employees/v1/validate", true, "-1.25e+2", "-1.25e+2", "1e-2", "1e-2")]
    public async Task Validation_PrimitiveStringBindingRetainsOriginalLexicalValues(
        string path, bool employee, string usernameJson, string username, string passwordJson, string password)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var row = await stores.SeedAsync(employee, rehash: false, username: username, password: password);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        using var response = await client.PostAsync(path, new StringContent(
            "{\"Username\":" + usernameJson + ",\"Password\":" + passwordJson + "}",
            System.Text.Encoding.UTF8, "application/json"));
        await AssertEmptySuccessAsync(response);
        foreach (var body in new[] { "{\"Username\":[],\"Password\":\"value\"}", "{\"Username\":\"source-user\",\"Password\":{}}" })
        {
            using var malformed = await client.PostAsync(path, new StringContent(body, System.Text.Encoding.UTF8, "application/json"));
            Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
        }
        var after = await stores.ReadAsync(employee);
        Assert.Equal(row.PasswordHash, after.PasswordHash);
        AssertUnchangedEligibility(row, after);
        Assert.Equal(0, await stores.State.RefreshSessions.CountAsync());
        Assert.Equal(0, await stores.State.IdentityActionTokens.CountAsync());
    }

    [Theory]
    [InlineData("/customers/v1/validate", false, "{'Username':'source-user','Password':'source-validation-test-password'}", "source-user", Password)]
    [InlineData("/Employees/v1/validate", true, "{'Username':'source-user','Password':'source-validation-test-password'}", "source-user", Password)]
    [InlineData("/customers/v1/validate", false, "{/*source*/Username:'source-user',Password:'source-validation-test-password',}", "source-user", Password)]
    [InlineData("/Employees/v1/validate", true, "{/*source*/Username:'source-user',Password:'source-validation-test-password',}", "source-user", Password)]
    [InlineData("/customers/v1/validate", false, "{Username:0x10,Password:NaN}", "0x10", "NaN")]
    [InlineData("/Employees/v1/validate", true, "{Username:0x10,Password:NaN}", "0x10", "NaN")]
    [InlineData("/customers/v1/validate", false, "{Username:Infinity,Password:-Infinity}", "Infinity", "-Infinity")]
    [InlineData("/Employees/v1/validate", true, "{Username:Infinity,Password:-Infinity}", "Infinity", "-Infinity")]
    [InlineData("/customers/v1/validate", false, "{'Username':'source-user','Password':'correct','Password':null}", "source-user", "correct")]
    [InlineData("/Employees/v1/validate", true, "{'Username':'source-user','Password':'correct','Password':null}", "source-user", "correct")]
    [InlineData("/customers/v1/validate", false, "{'Username':'source-user','Password':'source-validation-test-password'} {'ignored':true}", "source-user", Password)]
    [InlineData("/Employees/v1/validate", true, "{'Username':'source-user','Password':'source-validation-test-password'} {'ignored':true}", "source-user", Password)]
    public async Task Validation_OriginalNewtonsoftGrammarUsesTheSourceSerializer(
        string path, bool employee, string body, string username, string password)
    {
        // Characterize original MVC settings against the actual original serializer before the HTTP assertion.
        var oracle = Newtonsoft.Json.JsonSerializer.Create(new Newtonsoft.Json.JsonSerializerSettings
        {
            ContractResolver = new Newtonsoft.Json.Serialization.DefaultContractResolver
            {
                NamingStrategy = new Newtonsoft.Json.Serialization.CamelCaseNamingStrategy(),
            },
            MissingMemberHandling = Newtonsoft.Json.MissingMemberHandling.Ignore,
            TypeNameHandling = Newtonsoft.Json.TypeNameHandling.None,
            MaxDepth = 32,
            NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore,
            ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore,
        });
        using var sourceText = new StringReader(body);
        using var sourceReader = new Newtonsoft.Json.JsonTextReader(sourceText);
        var original = oracle.Deserialize<OriginalRequest>(sourceReader);
        Assert.NotNull(original);
        Assert.Equal(username, original.Username);
        Assert.Equal(password, original.Password);

        await using var stores = await Stores.CreateAsync(postgres);
        var row = await stores.SeedAsync(employee, rehash: false, username: username, password: password);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        using var response = await client.PostAsync(path, new StringContent(body, System.Text.Encoding.UTF8, "application/json"));
        await AssertEmptySuccessAsync(response);
        using var textJson = await client.PostAsync(path, new StringContent(body, System.Text.Encoding.Unicode, "text/json"));
        await AssertEmptySuccessAsync(textJson);
        using var vendorJson = await client.PostAsync(path, new StringContent(body, System.Text.Encoding.UTF8, "application/vnd.legacy-validation+json"));
        await AssertEmptySuccessAsync(vendorJson);
        using var malformed = await client.PostAsync(path, new StringContent(
            "{'Username':'private-username-sentinel','Password':['private-password-sentinel']}",
            System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
        var error = await malformed.Content.ReadAsStringAsync();
        Assert.DoesNotContain("private-username-sentinel", error, StringComparison.Ordinal);
        Assert.DoesNotContain("private-password-sentinel", error, StringComparison.Ordinal);
        var after = await stores.ReadAsync(employee);
        Assert.Equal(row.PasswordHash, after.PasswordHash);
        AssertUnchangedEligibility(row, after);
        Assert.Equal(0, await stores.State.RefreshSessions.CountAsync());
        Assert.Equal(0, await stores.State.IdentityActionTokens.CountAsync());
    }

    private sealed class OriginalRequest
    {
        public string? Username { get; set; }
        public string? Password { get; set; }
    }

    private static async Task AssertEmptySuccessAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsByteArrayAsync());
        Assert.False(response.Headers.Contains("Set-Cookie"));
        Assert.False(response.Headers.Contains("Authorization"));
        Assert.Null(response.Headers.Location);
    }

    private static void AssertUnchangedEligibility(LegacyIdentityRow before, LegacyIdentityRow after)
    {
        Assert.Equal(before.Id, after.Id);
        Assert.Equal(before.UserName, after.UserName);
        Assert.Equal(before.Email, after.Email);
        Assert.Equal(before.EmailConfirmed, after.EmailConfirmed);
        Assert.Equal(before.PasswordSetupRequired, after.PasswordSetupRequired);
        Assert.Equal(before.TwoFactorEnabled, after.TwoFactorEnabled);
        Assert.Equal(before.AccessFailedCount, after.AccessFailedCount);
        Assert.Equal(before.LockoutEnabled, after.LockoutEnabled);
        Assert.Equal(before.LockoutEnd, after.LockoutEnd);
    }

    private sealed class ConcurrentHasher(Action intervene) : IPasswordHasher<LegacyIdentityRow>
    {
        private readonly PasswordHasher<LegacyIdentityRow> real = new();
        public int Interventions { get; private set; }
        public string HashPassword(LegacyIdentityRow user, string password) => real.HashPassword(user, password);
        public PasswordVerificationResult VerifyHashedPassword(LegacyIdentityRow user, string hashedPassword, string providedPassword)
        {
            var result = real.VerifyHashedPassword(user, hashedPassword, providedPassword);
            if (result == PasswordVerificationResult.SuccessRehashNeeded && Interventions == 0)
            {
                Interventions++;
                intervene();
            }
            return result;
        }
    }

    private sealed class Factory(Stores stores, IPasswordHasher<LegacyIdentityRow>? hasher = null) : WebApplicationFactory<Program>
    {
        private readonly RSA signing = RSA.Create(2048);
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Production");
            builder.ConfigureLogging(logging => logging.ClearProviders());
            foreach (var setting in new Dictionary<string, string?>
            {
                ["ConnectionStrings:EmployeeIdentity"] = stores.Employees.Database.GetConnectionString(),
                ["ConnectionStrings:CustomerIdentity"] = stores.Customers.Database.GetConnectionString(),
                ["ConnectionStrings:RefreshSessions"] = stores.State.Database.GetConnectionString(),
                ["CORS:AllowedOrigins"] = "https://localhost",
                ["CORS:AllowedOrigins:0"] = "https://localhost",
                ["Jwt:Issuer"] = "https://validation.test",
                ["Jwt:Audience"] = "validation-test",
                ["Jwt:PrivateKeyPem"] = signing.ExportPkcs8PrivateKeyPem(),
                ["Jwt:KeyId"] = "validation-test",
                ["Jwt:AccessTokenLifetimeSeconds"] = "900",
            }) builder.UseSetting(setting.Key, setting.Value);
            if (hasher is not null)
            {
                builder.ConfigureTestServices(services =>
                {
                    services.RemoveAll<IPasswordHasher<LegacyIdentityRow>>();
                    services.AddSingleton(hasher);
                });
            }
        }

        public override async ValueTask DisposeAsync()
        {
            try { await base.DisposeAsync(); }
            finally { signing.Dispose(); }
        }
    }


    private sealed class Stores : IAsyncDisposable
    {
        private Stores(CustomerIdentityDbContext customers, EmployeeIdentityDbContext employees, RefreshSessionDbContext state)
        {
            Customers = customers;
            Employees = employees;
            State = state;
        }
        public CustomerIdentityDbContext Customers { get; }
        public EmployeeIdentityDbContext Employees { get; }
        public RefreshSessionDbContext State { get; }
        public LegacyIdentityDbContext Context(bool employee) => employee ? Employees : Customers;
        public async Task<LegacyIdentityRow> ReadAsync(bool employee) =>
            await Context(employee).Users.AsNoTracking().SingleAsync();

        public async Task<LegacyIdentityRow> SeedAsync(bool employee, bool rehash, bool invalidEmail = false,
            string username = "source-user", string password = Password)
        {
            var user = new LegacyIdentityRow
            {
                Id = "source-identity",
                UserName = username,
                NormalizedUserName = username.Normalize().ToUpperInvariant(),
                Email = invalidEmail ? "invalid-email" : "source@validation.test",
                NormalizedEmail = "STALE@VALIDATION.TEST",
                EmailConfirmed = false,
                SecurityStamp = "original-security",
                ConcurrencyStamp = "original-version",
                TwoFactorEnabled = true,
                PasswordSetupRequired = !employee,
                AccessFailedCount = 4,
                LockoutEnabled = true,
                LockoutEnd = DateTimeOffset.UtcNow.AddDays(1),
            };
            var options = Options.Create(new PasswordHasherOptions
            {
                CompatibilityMode = rehash ? PasswordHasherCompatibilityMode.IdentityV2 : PasswordHasherCompatibilityMode.IdentityV3,
            });
            user.PasswordHash = new PasswordHasher<LegacyIdentityRow>(options).HashPassword(user, password);
            Context(employee).Users.Add(user);
            await Context(employee).SaveChangesAsync();
            return await ReadAsync(employee);
        }

        public static async Task<Stores> CreateAsync(PostgresFixture postgres)
        {
            CustomerIdentityDbContext? customers = null;
            EmployeeIdentityDbContext? employees = null;
            RefreshSessionDbContext? state = null;
            try
            {
                customers = await postgres.CreateCustomerContextAsync();
                employees = await postgres.CreateEmployeeContextAsync();
                state = await postgres.CreateStateContextAsync();
                return new Stores(customers, employees, state);
            }
            catch
            {
                try { if (state is not null) await state.DisposeAsync(); }
                finally
                {
                    try { if (employees is not null) await employees.DisposeAsync(); }
                    finally { if (customers is not null) await customers.DisposeAsync(); }
                }
                throw;
            }
        }

        public async ValueTask DisposeAsync()
        {
            try { await State.DisposeAsync(); }
            finally
            {
                try { await Employees.DisposeAsync(); }
                finally { await Customers.DisposeAsync(); }
            }
        }
    }
}
