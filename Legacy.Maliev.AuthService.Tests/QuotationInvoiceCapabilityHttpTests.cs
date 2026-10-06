using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Legacy.Maliev.AuthService.Infrastructure;
using Maliev.Aspire.ServiceDefaults.IAM;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Tokens;
using Npgsql;

namespace Legacy.Maliev.AuthService.Tests;

/// <summary>Normal signed HTTP route admission; no fabricated live-IAM positive authority.</summary>
[Collection(PostgresCollection.Name)]
public sealed class QuotationInvoiceCapabilityHttpTests(PostgresFixture postgres)
{
    private const string Endpoint = "/auth/v1/exchange/quotation-invoice-completion";
    private static readonly Guid Operation = Guid.Parse("d5743e1a-641b-4623-9dc3-57a82b4c7885");

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NormalInvoiceBoundCapability_ActualIssuerBindsFinancialProofAndPreservesUnboundContract(bool bound)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores, invoiceBoundary: bound);
        using var client = app.CreateObservedClient();
        var employee = await LoginAsync(client);
        var caller = await CallerAsync(client);
        var before = await SnapshotCapabilityStateAsync(stores);
        using var response = await SendAsync(client, caller, employee, invoiceId: bound ? 1234 : null);
        var issued = await AssertCapabilityAsync(response, app, 120);
        var jwt = app.ValidateCapability(issued.AccessToken);
        Assert.Equal(bound ? 2 : 0, app.FinancialRequests);
        Assert.Equal(1, app.IamRequests);
        if (bound)
        {
            Assert.Equal("1234", Assert.Single(jwt.Claims, value => value.Type == "invoice_id").Value);
            Assert.Equal("2026-10-06T04:00:00.0000000Z", Assert.Single(jwt.Claims, value => value.Type == "quotation_version").Value);
            Assert.Equal(new string('A', 64), Assert.Single(jwt.Claims, value => value.Type == "financial_binding").Value);
            Assert.Equal("invoice-creation-financial-v1", Assert.Single(jwt.Claims, value => value.Type == "financial_binding_version").Value);
        }
        else Assert.DoesNotContain(jwt.Claims, value => value.Type is "invoice_id" or "quotation_version" or "financial_binding" or "financial_binding_version");
        Assert.Equal(before, await SnapshotCapabilityStateAsync(stores));
    }

    [Theory]
    [InlineData("invoice", 403)]
    [InlineData("quotation", 403)]
    [InlineData("employee", 403)]
    [InlineData("issuer", 403)]
    [InlineData("operation", 503)]
    [InlineData("requester", 503)]
    public async Task NormalInvoiceBoundCapability_ForeignFinancialOwnershipNeverMints(string mutation, int expectedStatus)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores, invoiceBoundary: true, financialBody: FinancialProof(mutation));
        using var client = app.CreateObservedClient();
        var employee = await LoginAsync(client);
        var caller = await CallerAsync(client);
        var before = await SnapshotCapabilityStateAsync(stores);
        using var response = await SendAsync(client, caller, employee, invoiceId: 1234);
        await AssertOpaqueAsync(response, (HttpStatusCode)expectedStatus, employee);
        Assert.Equal(1, app.FinancialRequests);
        Assert.Equal(0, app.IamRequests);
        Assert.Equal(before, await SnapshotCapabilityStateAsync(stores));
    }

    [Theory]
    [InlineData("version")]
    [InlineData("duplicate")]
    [InlineData("extra")]
    [InlineData("string-id")]
    [InlineData("binding")]
    [InlineData("non-utc")]
    [InlineData("malformed")]
    [InlineData("oversize")]
    public async Task NormalInvoiceBoundCapability_AmbiguousOrMalformedReadbackIsUnavailable(string mutation)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores, invoiceBoundary: true, financialBody: FinancialProof(mutation));
        using var client = app.CreateObservedClient();
        var employee = await LoginAsync(client);
        var caller = await CallerAsync(client);
        var before = await SnapshotCapabilityStateAsync(stores);
        using var response = await SendAsync(client, caller, employee, invoiceId: 1234);
        await AssertOpaqueAsync(response, HttpStatusCode.ServiceUnavailable, employee);
        Assert.Equal(1, app.FinancialRequests);
        Assert.Equal(0, app.IamRequests);
        Assert.Equal(before, await SnapshotCapabilityStateAsync(stores));
    }

    [Fact]
    public async Task NormalInvoiceBoundCapability_MissingOwnWorkloadReadGrantNeverSendsFinancialRequest()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores, invoiceBoundary: true, missingFinancialGrant: true);
        using var client = app.CreateObservedClient();
        var employee = await LoginAsync(client);
        var caller = await CallerAsync(client);
        var before = await SnapshotCapabilityStateAsync(stores);
        using var response = await SendAsync(client, caller, employee, invoiceId: 1234);
        await AssertOpaqueAsync(response, HttpStatusCode.ServiceUnavailable, employee);
        Assert.Equal(0, app.FinancialRequests);
        Assert.Equal(0, app.IamRequests);
        Assert.Equal(before, await SnapshotCapabilityStateAsync(stores));
    }

    [Theory]
    [InlineData(404, 403)]
    [InlineData(409, 403)]
    [InlineData(401, 503)]
    [InlineData(403, 503)]
    [InlineData(500, 503)]
    [InlineData(302, 503)]
    public async Task NormalInvoiceBoundCapability_ReadbackAbsenceAndTransportFailureRemainDistinct(int upstreamStatus, int expectedStatus)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores, invoiceBoundary: true, financialStatus: (HttpStatusCode)upstreamStatus);
        using var client = app.CreateObservedClient();
        var employee = await LoginAsync(client);
        var caller = await CallerAsync(client);
        var before = await SnapshotCapabilityStateAsync(stores);
        using var response = await SendAsync(client, caller, employee, invoiceId: 1234);
        await AssertOpaqueAsync(response, (HttpStatusCode)expectedStatus, employee);
        Assert.Equal(1, app.FinancialRequests);
        Assert.Equal(0, app.IamRequests);
        Assert.Equal(before, await SnapshotCapabilityStateAsync(stores));
    }

    [Theory]
    [InlineData("customer")]
    [InlineData("service")]
    [InlineData("scoped")]
    public async Task NormalInvoiceBoundCapability_GenuineNonemployeeCredentialsNeverReachFinancialAuthority(string kind)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores, invoiceBoundary: true);
        using var client = app.CreateObservedClient();
        var caller = await CallerAsync(client);
        string credential;
        if (kind == "service") credential = await CallerAsync(client, "legacy-auth");
        else if (kind == "scoped")
        {
            var employee = await LoginAsync(client);
            using var unbound = await SendAsync(client, caller, employee);
            credential = (await AssertCapabilityAsync(unbound, app, 120)).AccessToken;
        }
        else
        {
            var row = new LegacyIdentityRow
            {
                Id = "bound-customer", UserName = "customer@capability.test", NormalizedUserName = "CUSTOMER@CAPABILITY.TEST",
                Email = "customer@capability.test", NormalizedEmail = "CUSTOMER@CAPABILITY.TEST", EmailConfirmed = true,
                SecurityStamp = "bound-customer-stamp", ConcurrencyStamp = "bound-customer-concurrency", LockoutEnabled = true,
            };
            row.PasswordHash = new Microsoft.AspNetCore.Identity.PasswordHasher<LegacyIdentityRow>().HashPassword(row, "bound-customer-credential");
            stores.Customers.Users.Add(row);
            await stores.Customers.SaveChangesAsync();
            using var login = await client.PostAsJsonAsync("/auth/v1/login", new LoginRequest(row.UserName!, "bound-customer-credential", IdentityKind.Customer));
            Assert.Equal(HttpStatusCode.OK, login.StatusCode);
            credential = (await login.Content.ReadFromJsonAsync<TokenResponse>())!.AccessToken;
        }
        var iamBefore = app.IamRequests;
        var before = await SnapshotCapabilityStateAsync(stores);
        using var response = await SendAsync(client, caller, credential, invoiceId: 1234);
        await AssertOpaqueAsync(response, HttpStatusCode.Unauthorized, credential);
        Assert.Equal(0, app.FinancialRequests);
        Assert.Equal(iamBefore, app.IamRequests);
        Assert.Equal(before, await SnapshotCapabilityStateAsync(stores));
    }

    [Theory]
    [InlineData("invoice")]
    [InlineData("binding")]
    [InlineData("version")]
    [InlineData("issuer")]
    [InlineData("employee")]
    public async Task NormalInvoiceBoundCapability_DirectSignerRejectsInvalidFinancialBinding(string mutation)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores);
        var proof = new InvoiceFinancialOwnership(1, Operation.ToString("D"), 84, 1234,
            "https://quotation-capability.test", "capability-employee", "service:legacy-intranet",
            "2026-10-06T04:00:00.0000000Z", new string('A', 64));
        proof = mutation switch
        {
            "invoice" => proof with { InvoiceId = 0 },
            "binding" => proof with { FinancialBinding = new string('a', 64) },
            "version" => proof with { OriginalQuotationVersion = "2026-10-06T04:00:00.0000000+00:00" },
            "issuer" => proof with { OriginIssuer = "https://foreign-issuer.test" },
            _ => proof with { EmployeeSubject = "another-employee" },
        };
        var signer = app.Services.GetRequiredService<IQuotationInvoiceAttachmentTokenIssuer>();
        Assert.ThrowsAny<ArgumentException>(() => signer.IssueQuotationInvoiceAttachment("capability-employee", proof, app.Clock.GetUtcNow(), 120));
        Assert.Equal(0, app.FinancialRequests);
        Assert.Equal(0, app.IamRequests);
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
    }

    [Theory]
    [InlineData("stamp", 401)]
    [InlineData("revoke", 401)]
    [InlineData("financial-drift", 503)]
    public async Task NormalInvoiceBoundCapability_ChangesDuringSecondFinancialReadNeverMint(string mutation, int expectedStatus)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores, invoiceBoundary: true, pauseSecondFinancial: true);
        using var client = app.CreateObservedClient();
        client.Timeout = TimeSpan.FromSeconds(30);
        var employee = await LoginAsync(client);
        var caller = await CallerAsync(client);
        using var abort = new CancellationTokenSource();
        var pending = SendAsync(client, caller, employee, cancellationToken: abort.Token, invoiceId: 1234);
        var responseObserved = false;
        try
        {
            var checkpoint = await Task.WhenAny(app.FinancialReached.Task, pending).WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Same(app.FinancialReached.Task, checkpoint);
            Assert.False(pending.IsCompleted);
            if (mutation == "stamp")
            {
                (await stores.Employees.Users.SingleAsync()).SecurityStamp = "independently-changed-stamp";
                await stores.Employees.SaveChangesAsync();
            }
            else if (mutation == "revoke")
            {
                (await stores.State.RefreshSessions.SingleAsync()).RevokedAt = app.Clock.GetUtcNow();
                await stores.State.SaveChangesAsync();
            }
            else app.SecondFinancialBody = FinancialProof().Replace(new string('A', 64), new string('B', 64), StringComparison.Ordinal);
            var before = await SnapshotCapabilityStateAsync(stores);
            app.FinancialRelease.TrySetResult();
            using var response = await pending;
            responseObserved = true;
            await AssertOpaqueAsync(response, (HttpStatusCode)expectedStatus, employee);
            Assert.Equal(2, app.FinancialRequests);
            Assert.Equal(1, app.IamRequests);
            Assert.Equal(before, await SnapshotCapabilityStateAsync(stores));
        }
        finally
        {
            app.FinancialRelease.TrySetResult();
            if (!responseObserved)
            {
                abort.Cancel();
                try { using var abandoned = await pending.WaitAsync(TimeSpan.FromSeconds(5)); }
                catch (TimeoutException)
                {
                    // Keep observation/disposal attached to the finite HTTP request if cancellation is delayed.
                    _ = pending.ContinueWith(completed =>
                    {
                        if (completed.IsCompletedSuccessfully) completed.Result.Dispose();
                        else _ = completed.Exception;
                    }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                }
                catch (Exception) { _ = pending.Exception; } // Preserve the original checkpoint/mutation failure.
            }
        }
    }

    private static string FinancialProof(string? mutation = null)
    {
        var body = System.Text.Json.Nodes.JsonNode.Parse(System.Text.Json.JsonSerializer.Serialize(new
        {
            ContractVersion = 1, OperationId = Operation.ToString("D"), QuotationId = 84, InvoiceId = 1234,
            OriginIssuer = "https://quotation-capability.test", EmployeeSubject = "capability-employee",
            RequesterSubject = "service:legacy-intranet", OriginalQuotationVersion = "2026-10-06T04:00:00.0000000Z",
            FinancialBinding = new string('A', 64),
        }))!.AsObject();
        switch (mutation)
        {
            case "invoice": body["InvoiceId"] = 1235; break;
            case "quotation": body["QuotationId"] = 85; break;
            case "employee": body["EmployeeSubject"] = "other-employee"; break;
            case "issuer": body["OriginIssuer"] = "https://other-issuer.test"; break;
            case "operation": body["OperationId"] = Guid.NewGuid().ToString("D"); break;
            case "requester": body["RequesterSubject"] = "service:legacy-accounting"; break;
            case "version": body["ContractVersion"] = 2; break;
            case "extra": body["CallerSuppliedAuthority"] = true; break;
            case "string-id": body["InvoiceId"] = "1234"; break;
            case "binding": body["FinancialBinding"] = new string('a', 64); break;
            case "non-utc": body["OriginalQuotationVersion"] = "2026-10-06T04:00:00.0000000+00:00"; break;
            case "malformed": return "{";
            case "oversize": return new string('x', 32769);
        }
        var json = body.ToJsonString();
        return mutation == "duplicate" ? json.Replace("\"InvoiceId\":1234", "\"InvoiceId\":1234,\"InvoiceId\":1234", StringComparison.Ordinal) : json;
    }

    private static async Task<string> SnapshotCapabilityStateAsync(Stores stores)
    {
        var identities = new List<Dictionary<string, object?>>();
        foreach (var context in new LegacyIdentityDbContext[] { stores.Employees, stores.Customers })
        {
            var properties = context.Model.FindEntityType(typeof(LegacyIdentityRow))!.GetProperties().OrderBy(value => value.Name).ToArray();
            foreach (var row in await context.Users.AsNoTracking().OrderBy(value => value.Id).ToListAsync())
                identities.Add(properties.ToDictionary(value => value.Name, value => value.PropertyInfo!.GetValue(row)));
        }
        return System.Text.Json.JsonSerializer.Serialize(new
        {
            Identities = identities,
            Sessions = await stores.State.RefreshSessions.AsNoTracking().OrderBy(value => value.Id).ToListAsync(),
            Actions = await stores.State.IdentityActionTokens.AsNoTracking().OrderBy(value => value.Id).ToListAsync(),
        });
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PersistedWrongOwnerOrCustomerSession_IsRejectedByExactSid(bool customerKind)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores);
        using var client = app.CreateObservedClient();
        var employee = await LoginAsync(client);
        var original = await stores.State.RefreshSessions.SingleAsync();
        var otherId = Guid.NewGuid();
        stores.State.RefreshSessions.Add(new RefreshSession
        {
            Id = otherId,
            FamilyId = Guid.NewGuid(),
            IdentityId = customerKind ? original.IdentityId : "other-employee",
            IdentityKind = customerKind ? IdentityKind.Customer : IdentityKind.Employee,
            SecurityStamp = original.SecurityStamp,
            TokenHash = new string('D', 64),
            CreatedAt = app.Clock.GetUtcNow(),
            ExpiresAt = app.Clock.GetUtcNow().AddDays(1),
        });
        await stores.State.SaveChangesAsync();
        employee = app.InvalidEmployee(employee, "sid-other", otherId);
        using var response = await SendAsync(client, await CallerAsync(client), employee);
        await AssertOpaqueAsync(response, HttpStatusCode.Unauthorized, employee);
        Assert.Equal(0, app.IamRequests);
        app.AssertStandardAdmissionOnly();
        Assert.Equal(2, await stores.State.RefreshSessions.CountAsync());
        Assert.All(await stores.State.RefreshSessions.AsNoTracking().ToListAsync(), x => Assert.Null(x.RevokedAt));
    }

    [Theory]
    [InlineData("subject")]
    [InlineData("kind")]
    public async Task ExactGrantWithAmbiguousSignedRequester_IsForbidden(string mutation)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores);
        using var client = app.CreateObservedClient();
        var employee = await LoginAsync(client);
        var caller = app.ChangeCaller(await CallerAsync(client), mutation);
        using var callerPayload = System.Text.Json.JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(caller.Split('.')[1]));
        Assert.Contains(callerPayload.RootElement.GetProperty("permissions").EnumerateArray(),
            x => x.GetString() == "legacy-auth.quotation-invoice-completion.issue");
        Assert.Equal(2, callerPayload.RootElement.EnumerateObject().Count(x => x.Name == (mutation == "subject" ? "sub" : "identity_kind")));
        using var response = await SendAsync(client, caller, employee);
        await AssertOpaqueAsync(response, HttpStatusCode.Forbidden, employee);
        Assert.Equal(0, app.IamRequests);
        app.AssertStandardAdmissionOnly();
        Assert.Equal(1, await stores.State.RefreshSessions.CountAsync());
        Assert.Null((await stores.State.RefreshSessions.AsNoTracking().SingleAsync()).RevokedAt);
    }

    [Theory]
    [InlineData("iat", "string")]
    [InlineData("nbf", "string")]
    [InlineData("exp", "string")]
    [InlineData("iat", "fraction")]
    [InlineData("nbf", "fraction")]
    [InlineData("exp", "fraction")]
    [InlineData("iat", "duplicate")]
    [InlineData("nbf", "duplicate")]
    [InlineData("exp", "duplicate")]
    public async Task SignedNonIntegerOrDuplicateNumericDate_IsRejectedBeforeLive(string field, string mutation)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores);
        using var client = app.CreateObservedClient();
        var employee = app.ChangeNumericDate(await LoginAsync(client), field, mutation);
        using var response = await SendAsync(client, await CallerAsync(client), employee);
        await AssertOpaqueAsync(response, HttpStatusCode.Unauthorized, employee);
        Assert.Equal(0, app.IamRequests);
        app.AssertStandardAdmissionOnly();
        Assert.Null((await stores.State.RefreshSessions.AsNoTracking().SingleAsync()).RevokedAt);
    }

    [Theory]
    [InlineData("empty-token")]
    [InlineData("oversize-token")]
    [InlineData("zero-quote")]
    [InlineData("invalid-operation")]
    [InlineData("uppercase-operation")]
    [InlineData("empty-operation")]
    public async Task DirectIssuance_InvalidWireReturnsInvalidRequestBeforeAuthority(string mutation)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores);
        using var client = app.CreateObservedClient();
        await using var scope = app.Services.CreateAsyncScope();
        var service = scope.ServiceProvider.GetRequiredService<QuotationInvoiceCapabilityService>();
        var request = new QuotationInvoiceCapabilityRequest(
            mutation == "empty-token" ? "" : mutation == "oversize-token" ? new string('x', 16385) : "untrusted-token",
            mutation == "zero-quote" ? 0 : 84,
            mutation == "invalid-operation" ? "not-a-guid" : mutation == "uppercase-operation" ? Operation.ToString("D").ToUpperInvariant()
                : mutation == "empty-operation" ? Guid.Empty.ToString("D") : Operation.ToString("D"));
        var result = await service.IssueAsync(new ClaimsPrincipal(), null, request, CancellationToken.None);
        Assert.Equal("InvalidRequest", result.Status.ToString());
        Assert.Null(result.Token);
        Assert.Equal(0, app.ExchangeRequests);
        Assert.Equal(0, app.IamRequests);
        Assert.Equal(0, await stores.State.RefreshSessions.CountAsync());
    }

    [Theory]
    [InlineData("empty-subject")]
    [InlineData("service-subject")]
    [InlineData("zero-quote")]
    [InlineData("empty-operation")]
    [InlineData("zero-lifetime")]
    [InlineData("excess-lifetime")]
    public async Task DirectSigner_RejectsInvalidCapabilityBinding(string mutation)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores);
        using var client = app.CreateObservedClient();
        var signer = app.Services.GetRequiredService<IQuotationInvoiceCapabilityTokenIssuer>();
        Assert.ThrowsAny<ArgumentException>(() => signer.IssueQuotationInvoiceCapability(
            mutation == "empty-subject" ? "" : mutation == "service-subject" ? "service:legacy-intranet" : "capability-employee",
            mutation == "zero-quote" ? 0 : 84,
            mutation == "empty-operation" ? Guid.Empty : Operation,
            app.Clock.GetUtcNow(), mutation == "zero-lifetime" ? 0 : mutation == "excess-lifetime" ? 121 : 120));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EmployeeNotBefore_IsStrictAtInitialAndPostLiveClock(bool afterLive)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var clock = new ReversibleTestClock(DateTimeOffset.UtcNow);
        await using var app = new Factory(stores, pauseIam: afterLive, clockOverride: clock);
        using var client = app.CreateObservedClient();
        var employee = await LoginAsync(client);
        if (!afterLive) employee = app.InvalidEmployee(employee, "nbf-future");
        var pending = SendAsync(client, await CallerAsync(client), employee);
        try
        {
            if (afterLive)
            {
                await AwaitActualIamAsync(app, pending);
                clock.UtcNow = clock.GetUtcNow().AddSeconds(-5);
                app.IamRelease.TrySetResult();
            }
            using var response = await pending;
            await AssertOpaqueAsync(response, HttpStatusCode.Unauthorized, employee);
            Assert.Equal(afterLive ? 1 : 0, app.IamRequests);
            Assert.Null((await stores.State.RefreshSessions.AsNoTracking().SingleAsync()).RevokedAt);
        }
        finally { app.IamRelease.TrySetResult(); }
    }

    [Theory]
    [InlineData("signature")]
    [InlineData("audience")]
    [InlineData("subject")]
    [InlineData("kind")]
    [InlineData("sid-missing")]
    [InlineData("sid-other")]
    [InlineData("sid-duplicate")]
    [InlineData("iat-missing")]
    [InlineData("iat-future")]
    [InlineData("user-id")]
    [InlineData("locked")]
    public async Task InvalidEmployeeCredential_IsUnauthorizedBeforeEmployeeLiveAuthority(string mutation)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores);
        using var client = app.CreateObservedClient();
        var employee = await LoginAsync(client);
        if (mutation == "locked")
        {
            var identity = await stores.Employees.Users.SingleAsync();
            identity.LockoutEnabled = true;
            identity.LockoutEnd = app.Clock.GetUtcNow().AddHours(1);
            await stores.Employees.SaveChangesAsync();
        }
        else employee = app.InvalidEmployee(employee, mutation);
        using var response = await SendAsync(client, await CallerAsync(client), employee);
        await AssertOpaqueAsync(response, HttpStatusCode.Unauthorized, employee);
        app.AssertStandardAdmissionOnly();
        Assert.Equal(0, app.IamRequests);
        Assert.Null((await stores.State.RefreshSessions.AsNoTracking().SingleAsync()).RevokedAt);
    }

    [Fact]
    public async Task ActiveEmployee_MissingLiveAuthorityReturns503_NotAnAbsentExchange()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores, missingLive: true);
        using var client = app.CreateObservedClient();
        await using var normalScope = app.Services.CreateAsyncScope();
        Assert.IsType<IamServiceClient>(normalScope.ServiceProvider.GetRequiredService<IIamServiceClient>());
        using var normalIam = normalScope.ServiceProvider.GetRequiredService<IHttpClientFactory>().CreateClient("IAMService");
        Assert.Equal(new Uri("https+http://IAMService"), normalIam.BaseAddress);
        var employee = await LoginAsync(client);
        var caller = await CallerAsync(client);
        using (var original = await SendAsync(client, caller, employee, "/auth/v1/exchange/invoice-create"))
            await AssertOriginalInvoiceAsync(original, app);
        var row = await stores.State.RefreshSessions.AsNoTracking().SingleAsync();
        Assert.Equal("capability-employee", row.IdentityId);
        Assert.Equal(IdentityKind.Employee, row.IdentityKind);
        Assert.Null(row.RevokedAt);
        using var response = await SendAsync(client, caller, employee);
        await AssertOpaqueAsync(response, HttpStatusCode.ServiceUnavailable, employee);
        Assert.Equal(0, app.ExchangeRequests);
        Assert.Equal(0, app.StandardAdmissionRequests);
        Assert.Equal(0, app.IamRequests);
        Assert.Equal(1, await stores.State.RefreshSessions.CountAsync());
        Assert.Null((await stores.State.RefreshSessions.AsNoTracking().SingleAsync()).RevokedAt);
    }

    [Theory]
    [InlineData("revoked")]
    [InlineData("stamp")]
    [InlineData("family")]
    public async Task CurrentEmployeeAuthorityInvalid_NewExchangeAndOriginalInvoiceDeny(string change)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores);
        using var client = app.CreateObservedClient();
        var employee = await LoginAsync(client);
        var caller = await CallerAsync(client);
        var session = await stores.State.RefreshSessions.SingleAsync();
        if (change == "revoked") session.RevokedAt = DateTimeOffset.UtcNow;
        if (change == "stamp") (await stores.Employees.Users.SingleAsync()).SecurityStamp = "rotated-capability-stamp";
        if (change == "family") stores.State.RefreshSessions.Add(new RefreshSession
        {
            Id = Guid.NewGuid(),
            FamilyId = session.FamilyId,
            IdentityId = session.IdentityId,
            IdentityKind = IdentityKind.Employee,
            SecurityStamp = session.SecurityStamp,
            TokenHash = new string('B', 64),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(1),
            RevokedAt = DateTimeOffset.UtcNow,
        });
        await stores.Employees.SaveChangesAsync();
        await stores.State.SaveChangesAsync();
        using (var original = await SendAsync(client, caller, employee, "/auth/v1/exchange/invoice-create"))
            await AssertOpaqueAsync(original, HttpStatusCode.Unauthorized, employee);
        using var response = await SendAsync(client, caller, employee);
        await AssertOpaqueAsync(response, HttpStatusCode.Unauthorized, employee);
    }

    [Theory]
    [InlineData(0, "d5743e1a-641b-4623-9dc3-57a82b4c7885")]
    [InlineData(84, "D5743E1A-641B-4623-9DC3-57A82B4C7885")]
    [InlineData(84, "00000000-0000-0000-0000-000000000000")]
    public async Task InvalidQuoteOrOperation_Returns400(int quote, string operation)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores);
        using var client = app.CreateObservedClient();
        var employee = await LoginAsync(client);
        using var response = await SendAsync(client, await CallerAsync(client), employee, quote: quote, operation: operation);
        await AssertOpaqueAsync(response, HttpStatusCode.BadRequest, employee);
    }

    [Fact]
    public async Task AccountingCannotIssueIntranetCapability_Returns403()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores);
        using var client = app.CreateObservedClient();
        var employee = await LoginAsync(client);
        using var response = await SendAsync(client, await CallerAsync(client, "legacy-accounting"), employee);
        await AssertOpaqueAsync(response, HttpStatusCode.Forbidden, employee);
    }

    [Fact]
    public async Task AnonymousCannotExchange_Returns401()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores);
        using var client = app.CreateObservedClient();
        var employee = await LoginAsync(client);
        using var response = await SendAsync(client, null, employee);
        await AssertOpaqueAsync(response, HttpStatusCode.Unauthorized, employee);
    }

    [Fact]
    public async Task InvoicePermissionAlone_PreservesInvoiceExchange_ButCannotIssueQuotationCapability()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores);
        using var client = app.CreateObservedClient();
        var employee = app.RemoveQuotationPermission(await LoginAsync(client));
        var caller = await CallerAsync(client);
        using (var original = await SendAsync(client, caller, employee, "/auth/v1/exchange/invoice-create"))
            await AssertOriginalInvoiceAsync(original, app);
        using var response = await SendAsync(client, caller, employee);
        await AssertOpaqueAsync(response, HttpStatusCode.Forbidden, employee);
    }

    [Fact]
    public async Task Registered129Harness_UsesNormalOwnLoginAndUncachedEmployeeWire()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores);
        using var client = app.CreateObservedClient();
        var employee = await LoginAsync(client);
        var caller = await CallerAsync(client);
        using (var old = await SendAsync(client, caller, employee, "/auth/v1/exchange/invoice-create")) await AssertOriginalInvoiceAsync(old, app);
        await using var scope = app.Services.CreateAsyncScope();
        var authority = scope.ServiceProvider.GetRequiredService<IQuotationInvoiceLiveAuthorityClient>();
        Assert.Equal(QuotationInvoiceLiveAuthorityResult.Allowed, await authority.CheckAsync("capability-employee", 84));
        Assert.Equal(QuotationInvoiceLiveAuthorityResult.Allowed, await authority.CheckAsync("capability-employee", 84));
        Assert.Equal(1, app.ExchangeRequests);
        Assert.Equal(2, app.IamRequests);
        Assert.Equal(1, await stores.State.RefreshSessions.CountAsync());
    }

    [Theory]
    [InlineData("maximum", 120)]
    [InlineData("employee", 30)]
    [InlineData("session", 45)]
    public async Task LiveAllow_IssuesOnlySeparateBoundedCapability(string bound, int maximumSeconds)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores);
        using var client = app.CreateObservedClient();
        var employee = await LoginAsync(client);
        if (bound == "employee") employee = app.ChangeEmployee(employee, lifetimeSeconds: 30);
        if (bound == "session")
        {
            (await stores.State.RefreshSessions.SingleAsync()).ExpiresAt = app.Clock.GetUtcNow().AddSeconds(45);
            await stores.State.SaveChangesAsync();
        }
        using var response = await SendAsync(client, await CallerAsync(client), employee);
        var issued = await AssertCapabilityAsync(response, app, maximumSeconds);
        Assert.Equal(1, app.IamRequests);
        Assert.Equal(1, app.ExchangeRequests);
        Assert.Null((await stores.State.RefreshSessions.AsNoTracking().SingleAsync()).RevokedAt);
        Assert.Equal("capability-stamp", (await stores.Employees.Users.AsNoTracking().SingleAsync()).SecurityStamp);
        app.Clock.Advance(TimeSpan.FromSeconds(maximumSeconds));
        Assert.Throws<SecurityTokenInvalidLifetimeException>(() => app.ValidateCapability(issued.AccessToken));
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound, 1)]
    [InlineData(HttpStatusCode.Unauthorized, 3)]
    [InlineData(HttpStatusCode.Forbidden, 3)]
    public async Task RepeatedAuthorizedRequest_RechecksLiveAuthorityAndPreservesWorkloadInvalidation(HttpStatusCode admissionStatus, int expectedExchanges)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores, standardAdmissionStatus: admissionStatus);
        using var client = app.CreateObservedClient();
        var employee = await LoginAsync(client);
        var caller = await CallerAsync(client);
        using var first = await SendAsync(client, caller, employee);
        var firstToken = await AssertCapabilityAsync(first, app, 120);
        using var second = await SendAsync(client, caller, employee);
        var secondToken = await AssertCapabilityAsync(second, app, 120);
        Assert.NotEqual(app.ValidateCapability(firstToken.AccessToken).Id, app.ValidateCapability(secondToken.AccessToken).Id);
        Assert.Equal(2, app.IamRequests);
        Assert.Equal(expectedExchanges, app.ExchangeRequests);
        app.AssertRepeatedAuthorityOrder(expectedExchanges);
        Assert.Equal(1, await stores.State.RefreshSessions.CountAsync());
    }

    [Theory]
    [InlineData("{\"allowed\":false}", 200, HttpStatusCode.Forbidden)]
    [InlineData("{}", 200, HttpStatusCode.ServiceUnavailable)]
    [InlineData("{\"allowed\":true,\"allowed\":false}", 200, HttpStatusCode.ServiceUnavailable)]
    [InlineData("{\"allowed\":true}", 500, HttpStatusCode.ServiceUnavailable)]
    public async Task LiveDenyOrUnavailable_NeverMintsFromStaticEmployeeGrants(string body, int upstreamStatus, HttpStatusCode expected)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores, body, iamStatus: (HttpStatusCode)upstreamStatus);
        using var client = app.CreateObservedClient();
        var employee = await LoginAsync(client);
        using var response = await SendAsync(client, await CallerAsync(client), employee);
        await AssertOpaqueAsync(response, expected, employee);
        Assert.Equal(1, app.IamRequests);
        Assert.Null((await stores.State.RefreshSessions.AsNoTracking().SingleAsync()).RevokedAt);
    }

    [Theory]
    [InlineData("missing-grant")]
    [InlineData("wildcard-grant")]
    [InlineData("executor")]
    public async Task SignedRequesterWithoutExactIssuanceAuthority_IsForbiddenBeforeEmployeeLiveIam(string change)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores);
        using var client = app.CreateObservedClient();
        var employee = await LoginAsync(client);
        var caller = app.ChangeCaller(await CallerAsync(client), change);
        using var response = await SendAsync(client, caller, employee);
        await AssertOpaqueAsync(response, HttpStatusCode.Forbidden, employee);
        Assert.Equal(0, app.IamRequests);
        app.AssertStandardAdmissionOnly();
        Assert.Equal(1, await stores.State.RefreshSessions.CountAsync());
        Assert.Null((await stores.State.RefreshSessions.AsNoTracking().SingleAsync()).RevokedAt);
    }

    [Theory]
    [InlineData("accounting-permission")]
    [InlineData("quotation-permission")]
    public async Task EmployeeRequiresBothOriginalAccountingAndQuotationPermission(string removed)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores);
        using var client = app.CreateObservedClient();
        var employee = app.ChangeEmployee(await LoginAsync(client), removed == "accounting-permission" ? "legacy.accounting.create" : "legacy.quotations.update");
        using var response = await SendAsync(client, await CallerAsync(client), employee);
        await AssertOpaqueAsync(response, HttpStatusCode.Forbidden, employee);
        Assert.Equal(0, app.IamRequests);
    }

    [Theory]
    [InlineData("revoked")]
    [InlineData("stamp")]
    [InlineData("family")]
    [InlineData("deleted")]
    [InlineData("unconfirmed")]
    [InlineData("locked")]
    [InlineData("employee-expired")]
    [InlineData("session-expired")]
    public async Task AuthorityChangesDuringLiveAwait_IsFreshlyRejectedBeforeSigning(string change)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores, pauseIam: true);
        using var client = app.CreateObservedClient();
        var employee = await LoginAsync(client);
        // Expiry is before the independent transport deadline, so the intended recheck is not masked by timeout.
        if (change == "employee-expired") employee = app.ChangeEmployee(employee, lifetimeSeconds: 5);
        if (change == "session-expired")
        {
            (await stores.State.RefreshSessions.SingleAsync()).ExpiresAt = app.Clock.GetUtcNow().AddSeconds(5);
            await stores.State.SaveChangesAsync();
        }
        var pending = SendAsync(client, await CallerAsync(client), employee);
        try
        {
            await AwaitActualIamAsync(app, pending);
            var session = await stores.State.RefreshSessions.SingleAsync();
            var identity = await stores.Employees.Users.SingleAsync();
            if (change == "revoked") session.RevokedAt = app.Clock.GetUtcNow();
            if (change == "stamp") identity.SecurityStamp = "changed-during-live-await";
            if (change == "family") stores.State.RefreshSessions.Add(new RefreshSession
            {
                Id = Guid.NewGuid(),
                FamilyId = session.FamilyId,
                IdentityId = session.IdentityId,
                IdentityKind = IdentityKind.Employee,
                SecurityStamp = session.SecurityStamp,
                TokenHash = new string('C', 64),
                CreatedAt = app.Clock.GetUtcNow(),
                ExpiresAt = app.Clock.GetUtcNow().AddDays(1),
                RevokedAt = app.Clock.GetUtcNow(),
            });
            if (change == "deleted") stores.Employees.Users.Remove(identity);
            if (change == "unconfirmed") identity.EmailConfirmed = false;
            if (change == "locked") identity.LockoutEnd = app.Clock.GetUtcNow().AddHours(1);
            await stores.Employees.SaveChangesAsync();
            await stores.State.SaveChangesAsync();
            if (change.EndsWith("-expired", StringComparison.Ordinal)) app.Clock.Advance(TimeSpan.FromSeconds(5));
            app.IamRelease.TrySetResult();
            using var response = await pending;
            await AssertOpaqueAsync(response, HttpStatusCode.Unauthorized, employee);
            Assert.Equal(1, app.IamRequests);
            Assert.Equal(change == "family" ? 2 : 1, await stores.State.RefreshSessions.CountAsync());
        }
        finally { app.IamRelease.TrySetResult(); }
    }

    [Fact]
    public async Task CallerAbortDuringActualLiveAwait_PropagatesWithoutCapability()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores, pauseIam: true);
        using var client = app.CreateObservedClient();
        using var abort = new CancellationTokenSource();
        var employee = await LoginAsync(client);
        var pending = SendAsync(client, await CallerAsync(client), employee, cancellationToken: abort.Token);
        try
        {
            await AwaitActualIamAsync(app, pending);
            abort.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
            await app.IamCancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Null((await stores.State.RefreshSessions.AsNoTracking().SingleAsync()).RevokedAt);
        }
        finally { app.IamRelease.TrySetResult(); }
    }

    private static async Task AwaitActualIamAsync(Factory app, Task<HttpResponseMessage> pending)
    {
        var first = await Task.WhenAny(app.IamReached.Task, pending).WaitAsync(TimeSpan.FromSeconds(5));
        if (first == pending)
        {
            using var response = await pending;
            Assert.Fail($"Actual live-IAM checkpoint was not reached before endpoint returned {(int)response.StatusCode}.");
        }
        Assert.Equal(1, app.IamRequests);
        Assert.False(pending.IsCompleted);
    }

    private static async Task<InvoiceDelegationTokenResponse> AssertCapabilityAsync(HttpResponseMessage response, Factory app, int maximumSeconds)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var issued = Assert.IsType<InvoiceDelegationTokenResponse>(await response.Content.ReadFromJsonAsync<InvoiceDelegationTokenResponse>());
        Assert.Equal("Bearer", issued.TokenType);
        Assert.InRange(issued.ExpiresIn, 1, maximumSeconds);
        var jwt = app.ValidateCapability(issued.AccessToken);
        Assert.Equal(["legacy-quotation:invoice-complete"], jwt.Audiences);
        Assert.Equal("capability-employee", jwt.Subject);
        Assert.Equal("legacy.quotation.invoice-complete", Assert.Single(jwt.Claims, x => x.Type == "scope").Value);
        Assert.Equal("service:legacy-intranet", Assert.Single(jwt.Claims, x => x.Type == "azp").Value);
        Assert.Equal("service:legacy-accounting", Assert.Single(jwt.Claims, x => x.Type == "executor").Value);
        Assert.Equal("84", Assert.Single(jwt.Claims, x => x.Type == "quotation_id").Value);
        Assert.Equal(Operation.ToString("D"), Assert.Single(jwt.Claims, x => x.Type == "operation_id").Value);
        Assert.True(Guid.TryParseExact(jwt.Id, "D", out var jti) && jti != Guid.Empty);
        var iat = long.Parse(Assert.Single(jwt.Claims, x => x.Type == "iat").Value, System.Globalization.CultureInfo.InvariantCulture);
        Assert.Equal(app.Clock.GetUtcNow().ToUnixTimeSeconds(), iat);
        Assert.Equal(iat, jwt.Payload.NotBefore!.Value);
        Assert.InRange(jwt.Payload.Expiration!.Value - iat, 1, maximumSeconds);
        Assert.Equal(jwt.Payload.Expiration.Value - iat, issued.ExpiresIn);
        Assert.DoesNotContain(jwt.Claims, x => x.Type is "sid" or "security_stamp" or "permissions" or "role" or "email" or "employee_access_token");
        return issued;
    }

    private static async Task<string> LoginAsync(HttpClient client)
    {
        using var response = await client.PostAsJsonAsync("/auth/v1/login", new LoginRequest("capability@example.test", "capability-test-password", IdentityKind.Employee));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return Assert.IsType<TokenResponse>(await response.Content.ReadFromJsonAsync<TokenResponse>()).AccessToken;
    }

    private static async Task<string> CallerAsync(HttpClient client, string name = "legacy-intranet")
    {
        using var response = await client.PostAsJsonAsync("/auth/v1/service/login", new ServiceLoginRequest(name, Factory.Secret));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return Assert.IsType<ServiceTokenResponse>(await response.Content.ReadFromJsonAsync<ServiceTokenResponse>()).AccessToken;
    }

    private static async Task<HttpResponseMessage> SendAsync(HttpClient client, string? caller, string employee,
        string path = Endpoint, int quote = 84, string? operation = null, CancellationToken cancellationToken = default, int? invoiceId = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = invoiceId is null
                ? JsonContent.Create(new { EmployeeAccessToken = employee, QuotationId = quote, OperationId = operation ?? Operation.ToString("D") })
                : JsonContent.Create(new { EmployeeAccessToken = employee, QuotationId = quote, OperationId = operation ?? Operation.ToString("D"), InvoiceId = invoiceId }),
        };
        if (caller is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", caller);
        return await client.SendAsync(request, cancellationToken);
    }

    private static async Task AssertOpaqueAsync(HttpResponseMessage response, HttpStatusCode expected, string employee)
    {
        Assert.Equal(expected, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain(employee, body, StringComparison.Ordinal);
        Assert.DoesNotContain("capability-employee", body, StringComparison.Ordinal);
        Assert.DoesNotContain("capability@example.test", body, StringComparison.Ordinal);
        Assert.DoesNotContain("accessToken", body, StringComparison.Ordinal);
    }

    private static async Task AssertOriginalInvoiceAsync(HttpResponseMessage response, Factory app)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var token = Assert.IsType<InvoiceDelegationTokenResponse>(await response.Content.ReadFromJsonAsync<InvoiceDelegationTokenResponse>());
        Assert.Equal("Bearer", token.TokenType);
        Assert.Equal(120, token.ExpiresIn);
        var jwt = app.ValidateInvoice(token.AccessToken);
        Assert.Equal("capability-employee", jwt.Subject);
        Assert.Equal(["legacy-accounting:invoice-create"], jwt.Audiences);
        Assert.Equal("legacy.accounting.create", Assert.Single(jwt.Claims, x => x.Type == "scope").Value);
        Assert.Equal("service:legacy-intranet", Assert.Single(jwt.Claims, x => x.Type == "azp").Value);
        Assert.Equal("84", Assert.Single(jwt.Claims, x => x.Type == "quotation_id").Value);
        Assert.Equal(Operation.ToString("D"), Assert.Single(jwt.Claims, x => x.Type == "operation_id").Value);
        Assert.DoesNotContain(jwt.Claims, x => x.Type is "executor" or "sid" or "permissions" or "employee_access_token");
    }

    private sealed class ReversibleTestClock(DateTimeOffset initial) : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = initial;
        public override DateTimeOffset GetUtcNow() => UtcNow;
    }

    private sealed class Factory(Stores stores, string iamBody = "{\"allowed\":true}", bool missingLive = false,
        bool pauseIam = false, HttpStatusCode iamStatus = HttpStatusCode.OK, TimeProvider? clockOverride = null,
        HttpStatusCode standardAdmissionStatus = HttpStatusCode.NotFound, bool invoiceBoundary = false,
        string? financialBody = null, HttpStatusCode financialStatus = HttpStatusCode.OK,
        bool missingFinancialGrant = false, bool pauseSecondFinancial = false) : WebApplicationFactory<Program>
    {
        public const string Secret = "capability-disposable-service-credential";
        private readonly RSA key = RSA.Create(2048);
        public FakeTimeProvider Clock { get; } = new(DateTimeOffset.UtcNow);
        // All machine workload exchanges, including standard service admission.
        public int ExchangeRequests { get; private set; }
        // Scoped employee live authority is counted separately from standard route admission.
        public int IamRequests { get; private set; }
        public int FinancialRequests { get; private set; }
        public string? SecondFinancialBody { get; set; }
        public TaskCompletionSource FinancialReached { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource FinancialRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int StandardAdmissionRequests { get; private set; }
        private int standardAdmissionFailures;
        private readonly ConcurrentQueue<string> boundaryOrder = new();
        private readonly ConcurrentQueue<string> issuedWorkloadIds = new();
        private readonly ConcurrentQueue<string> standardAdmissionFailureSites = new();
        private string? observedAdmissionRoute;

        public HttpClient CreateObservedClient() => CreateDefaultClient(new InboundRouteObserver(this));

        public void AssertRepeatedAuthorityOrder(int expectedExchanges)
        {
            Assert.Equal(2, StandardAdmissionRequests);
            Assert.Equal(expectedExchanges, issuedWorkloadIds.Count);
            Assert.Equal(expectedExchanges, issuedWorkloadIds.Distinct(StringComparer.Ordinal).Count());
            string[] expectedOrder = expectedExchanges == 1
                ? ["workload-token", "standard-service-admission", "scoped-employee-live-authority", "standard-service-admission", "scoped-employee-live-authority"]
                : ["workload-token", "standard-service-admission", "workload-token", "scoped-employee-live-authority", "standard-service-admission", "workload-token", "scoped-employee-live-authority"];
            Assert.Equal(expectedOrder, boundaryOrder.ToArray());
        }

        public void AssertStandardAdmissionOnly()
        {
            Assert.Equal(1, ExchangeRequests);
            Assert.Equal(1, StandardAdmissionRequests);
            Assert.Equal(0, IamRequests);
            Assert.Equal(["workload-token", "standard-service-admission"], boundaryOrder.ToArray());
        }
        public TaskCompletionSource IamReached { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource IamRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource IamCancelled { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("CORS:AllowedOrigins", "https://localhost");
            // The normal IAM origin is validated while Program composes the host.
            if (!missingLive) builder.UseSetting("Services:IAMService:BaseUrl", "https://capability-iam.test");
            builder.ConfigureAppConfiguration((_, config) =>
            {
                var values = new Dictionary<string, string?>
                {
                    ["ConnectionStrings:EmployeeIdentity"] = stores.Employees.Database.GetConnectionString(),
                    ["ConnectionStrings:CustomerIdentity"] = stores.Customers.Database.GetConnectionString(),
                    ["ConnectionStrings:RefreshSessions"] = stores.State.Database.GetConnectionString(),
                    ["Jwt:Issuer"] = "https://quotation-capability.test",
                    ["Jwt:Audience"] = "quotation-capability-access",
                    ["Jwt:PrivateKeyPem"] = key.ExportPkcs8PrivateKeyPem(),
                    ["Jwt:KeyId"] = "quotation-capability-key",
                    ["Jwt:AccessTokenLifetimeSeconds"] = "900",
                    ["ServiceClients:Clients:legacy-auth:SecretSha256"] = ServiceClientCredential.HashSecret(Secret),
                    ["ServiceClients:Clients:legacy-auth:Permissions:0"] = "legacy.iam.permissions.check",
                    ["ServiceAuthentication:ClientId"] = missingLive ? null : "legacy-auth",
                    ["ServiceAuthentication:ClientSecret"] = missingLive ? null : Secret,
                    ["Services:Auth:BaseUrl"] = missingLive ? null : "https://quotation-capability.test",
                    ["Services:IAMService:BaseUrl"] = missingLive ? null : "https://capability-iam.test",
                    ["IAM:LivePermissionChecks:Credential"] = missingLive ? null : "synthetic-capability-live-key",
                };
                if (invoiceBoundary)
                {
                    values["Services:AccountingService:BaseUrl"] = "https://capability-accounting.test";
                    if (!missingFinancialGrant)
                        values["ServiceClients:Clients:legacy-auth:Permissions:1"] = "legacy.accounting.invoice-financial-ownership.read";
                }
                foreach (var service in new[] { "legacy-intranet", "legacy-accounting" })
                {
                    values[$"ServiceClients:Clients:{service}:SecretSha256"] = ServiceClientCredential.HashSecret(Secret);
                    values[$"ServiceClients:Clients:{service}:Permissions:0"] = "legacy-auth.invoice-delegation.issue";
                    values[$"ServiceClients:Clients:{service}:Permissions:1"] = "legacy-auth.quotation-invoice-completion.issue";
                }
                config.AddInMemoryCollection(values);
            });
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<TimeProvider>();
                services.AddSingleton<TimeProvider>(clockOverride ?? Clock);
                services.AddSingleton<IHttpMessageHandlerBuilderFilter>(new BoundaryFilter(this));
            });
        }
        public string ChangeEmployee(string token, string? removePermission = null, int lifetimeSeconds = 600)
        {
            var parsed = new JwtSecurityTokenHandler().ReadJwtToken(token);
            var claims = parsed.Claims.Where(x => x.Type is not ("iss" or "aud" or "nbf" or "exp")
                && !(x.Type == "permissions" && x.Value == removePermission));
            return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(parsed.Issuer, parsed.Audiences.Single(), claims,
                Clock.GetUtcNow().UtcDateTime.AddSeconds(-1), Clock.GetUtcNow().UtcDateTime.AddSeconds(lifetimeSeconds),
                new SigningCredentials(new RsaSecurityKey(key), SecurityAlgorithms.RsaSha256)));
        }

        public string InvalidEmployee(string token, string mutation, Guid? otherSession = null)
        {
            var parsed = new JwtSecurityTokenHandler().ReadJwtToken(token);
            var claims = parsed.Claims.Where(x => x.Type is not ("iss" or "aud" or "nbf" or "exp")).ToList();
            if (mutation == "subject") claims.Add(new Claim("sub", "other-employee"));
            if (mutation == "kind") claims.Add(new Claim("identity_kind", "customer"));
            if (mutation is "sid-missing" or "sid-other") claims.RemoveAll(x => x.Type == "sid");
            if (mutation is "sid-other" or "sid-duplicate") claims.Add(new Claim("sid", (otherSession ?? Guid.NewGuid()).ToString("D")));
            if (mutation is "iat-missing" or "iat-future") claims.RemoveAll(x => x.Type == "iat");
            if (mutation == "iat-future") claims.Add(new Claim("iat", Clock.GetUtcNow().AddMinutes(2).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64));
            if (mutation == "user-id") claims.Add(new Claim("user_id", "other-employee"));
            using var foreign = RSA.Create(2048);
            return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(parsed.Issuer,
                mutation == "audience" ? "untrusted-audience" : parsed.Audiences.Single(), claims,
                Clock.GetUtcNow().UtcDateTime.AddSeconds(mutation == "nbf-future" ? 5 : -1), Clock.GetUtcNow().UtcDateTime.AddMinutes(10),
                new SigningCredentials(new RsaSecurityKey(mutation == "signature" ? foreign : key), SecurityAlgorithms.RsaSha256)));
        }

        public string ChangeNumericDate(string token, string field, string mutation)
        {
            var parsed = new JwtSecurityTokenHandler().ReadJwtToken(token);
            var original = Convert.ToInt64(parsed.Payload[field], System.Globalization.CultureInfo.InvariantCulture);
            if (mutation == "string") parsed.Payload[field] = original.ToString(System.Globalization.CultureInfo.InvariantCulture);
            if (mutation == "fraction") parsed.Payload[field] = original + 0.5;
            var payload = parsed.Payload.SerializeToJson();
            if (mutation == "duplicate") payload = payload[..^1] + ",\"" + field + "\":" + original.ToString(System.Globalization.CultureInfo.InvariantCulture) + "}";
            var signingInput = Base64UrlEncoder.Encode(parsed.Header.SerializeToJson()) + "." + Base64UrlEncoder.Encode(payload);
            return signingInput + "." + Base64UrlEncoder.Encode(key.SignData(System.Text.Encoding.ASCII.GetBytes(signingInput),
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }
        public string ChangeCaller(string token, string mutation)
        {
            var parsed = new JwtSecurityTokenHandler().ReadJwtToken(token);
            if (mutation is "subject" or "kind")
            {
                var field = mutation == "subject" ? "sub" : "identity_kind";
                var value = mutation == "subject" ? "service:legacy-intranet" : "service";
                var payload = parsed.Payload.SerializeToJson();
                payload = payload[..^1] + ",\"" + field + "\":\"" + value + "\"}";
                var signingInput = Base64UrlEncoder.Encode(parsed.Header.SerializeToJson()) + "." + Base64UrlEncoder.Encode(payload);
                return signingInput + "." + Base64UrlEncoder.Encode(key.SignData(System.Text.Encoding.ASCII.GetBytes(signingInput),
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            }
            var claims = parsed.Claims.Where(x => x.Type is not ("iss" or "aud" or "nbf" or "exp")
                && !((mutation is "missing-grant" or "wildcard-grant" or "executor")
                    && x.Type == "permissions" && x.Value == "legacy-auth.quotation-invoice-completion.issue")).ToList();
            if (mutation == "wildcard-grant") claims.Add(new Claim("permissions", "legacy-auth.*"));
            if (mutation == "executor")
            {
                claims.Add(new Claim("permissions", "legacy-auth.quotation-invoice-completion.issue"));
                claims.Add(new Claim("executor", "service:legacy-accounting"));
            }
            return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(parsed.Issuer, parsed.Audiences.Single(), claims,
                Clock.GetUtcNow().UtcDateTime.AddSeconds(-1), Clock.GetUtcNow().UtcDateTime.AddMinutes(10),
                new SigningCredentials(new RsaSecurityKey(key), SecurityAlgorithms.RsaSha256)));
        }

        public JwtSecurityToken ValidateCapability(string token)
        {
            new JwtSecurityTokenHandler { MapInboundClaims = false }.ValidateToken(token, new TokenValidationParameters
            {
                ValidIssuer = "https://quotation-capability.test",
                ValidAudience = "legacy-quotation:invoice-complete",
                IssuerSigningKey = new RsaSecurityKey(key),
                ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                RequireSignedTokens = true,
                RequireExpirationTime = true,
                ClockSkew = TimeSpan.Zero,
                LifetimeValidator = (nbf, exp, _, _) => exp > Clock.GetUtcNow().UtcDateTime && (nbf is null || nbf <= Clock.GetUtcNow().UtcDateTime),
            }, out var validated);
            return Assert.IsType<JwtSecurityToken>(validated);
        }

        private void ValidateOwnMachine(string token)
        {
            var principal = new JwtSecurityTokenHandler { MapInboundClaims = false }.ValidateToken(token, new TokenValidationParameters
            {
                ValidIssuer = "https://quotation-capability.test",
                ValidAudience = "quotation-capability-access",
                IssuerSigningKey = new RsaSecurityKey(key),
                ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                RequireSignedTokens = true,
                RequireExpirationTime = true,
                ClockSkew = TimeSpan.Zero,
            }, out var verified);
            Assert.Equal(["quotation-capability-access"], Assert.IsType<JwtSecurityToken>(verified).Audiences);
            Assert.Equal("service:legacy-auth", Assert.Single(principal.Claims, x => x.Type == "sub").Value);
            Assert.Equal("service", Assert.Single(principal.Claims, x => x.Type == "identity_kind").Value);
            Assert.Equal(invoiceBoundary && !missingFinancialGrant
                ? new[] { "legacy.iam.permissions.check", "legacy.accounting.invoice-financial-ownership.read" }
                : new[] { "legacy.iam.permissions.check" }, principal.FindAll("permissions").Select(value => value.Value));
            Assert.DoesNotContain(principal.Claims, x => x.Type is "sid" or "executor");
        }

        private async Task<HttpResponseMessage> ExchangeAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            ExchangeRequests++;
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal("https://quotation-capability.test/auth/v1/service/login", request.RequestUri!.AbsoluteUri);
            Assert.Null(request.Headers.Authorization);
            using var body = System.Text.Json.JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
            Assert.Equal("legacy-auth", body.RootElement.GetProperty("clientId").GetString());
            Assert.Equal(Secret, body.RootElement.GetProperty("clientSecret").GetString());
            using var actual = CreateClient();
            using var forwarded = new HttpRequestMessage(request.Method, request.RequestUri)
            {
                Content = new StringContent(body.RootElement.GetRawText(), System.Text.Encoding.UTF8, "application/json"),
            };
            var response = await actual.SendAsync(forwarded, cancellationToken);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
            var parsed = Assert.IsType<ServiceTokenResponse>(System.Text.Json.JsonSerializer.Deserialize<ServiceTokenResponse>(bytes, new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web)));
            ValidateOwnMachine(parsed.AccessToken);
            issuedWorkloadIds.Enqueue(new JwtSecurityTokenHandler().ReadJwtToken(parsed.AccessToken).Id);
            boundaryOrder.Enqueue("workload-token");
            response.Content.Dispose();
            response.Content = new ByteArrayContent(bytes);
            response.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
            return response;
        }

        private async Task<HttpResponseMessage> StandardAdmissionAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            try { return await ValidateStandardAdmissionAsync(request, cancellationToken); }
            catch (Exception exception)
            {
                standardAdmissionFailures++;
                standardAdmissionFailureSites.Enqueue(exception.StackTrace ?? exception.GetType().Name);
                throw;
            }
        }

        private async Task<HttpResponseMessage> ValidateStandardAdmissionAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            StandardAdmissionRequests++;
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal("https://capability-iam.test/iam/v1/auth/check-permission", request.RequestUri!.AbsoluteUri);
            Assert.Equal("Bearer", request.Headers.Authorization!.Scheme);
            ValidateOwnMachine(request.Headers.Authorization.Parameter!);
            Assert.False(request.Headers.Contains("X-Maliev-IAM-Live-Check-Key"));
            using var body = System.Text.Json.JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
            var root = body.RootElement;
            Assert.Contains(root.GetProperty("principalId").GetString(), new[] { "service:legacy-intranet", "service:legacy-accounting" });
            var route = observedAdmissionRoute;
            Assert.Contains(route, new[] { Endpoint, "/auth/v1/exchange/invoice-create" });
            Assert.Equal(route == Endpoint ? QuotationInvoiceCapabilityContract.IssuePermission : LegacyAccessTokenPermissions.InvoiceDelegationIssue,
                root.GetProperty("permissionId").GetString());
            Assert.Equal("global", root.GetProperty("resourcePath").GetString());
            Assert.False(root.GetProperty("bypassCache").GetBoolean());
            // Default 404 models an unavailable route, without a grant or cached denial.
            // Explicit 401/403 controls retain real token invalidation
            // before the separate scoped live check. No production token policy is replaced.
            boundaryOrder.Enqueue("standard-service-admission");
            return new(standardAdmissionStatus);
        }

        private async Task<HttpResponseMessage> IamAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            IamRequests++;
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal("https://capability-iam.test/iam/v1/auth/check-permission", request.RequestUri!.AbsoluteUri);
            Assert.Equal("Bearer", request.Headers.Authorization!.Scheme);
            ValidateOwnMachine(request.Headers.Authorization.Parameter!);
            Assert.Equal("synthetic-capability-live-key", Assert.Single(request.Headers.GetValues("X-Maliev-IAM-Live-Check-Key")));
            using var body = System.Text.Json.JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
            Assert.Equal("capability-employee", body.RootElement.GetProperty("principalId").GetString());
            Assert.Equal("legacy.quotations.update", body.RootElement.GetProperty("permissionId").GetString());
            Assert.Equal("/quotations/84", body.RootElement.GetProperty("resourcePath").GetString());
            Assert.True(body.RootElement.GetProperty("bypassCache").GetBoolean());
            boundaryOrder.Enqueue("scoped-employee-live-authority");
            IamReached.TrySetResult();
            if (pauseIam)
            {
                try { await IamRelease.Task.WaitAsync(cancellationToken); }
                catch (OperationCanceledException) { IamCancelled.TrySetResult(); throw; }
            }
            return new HttpResponseMessage(iamStatus)
            {
                Content = new StringContent(iamBody, System.Text.Encoding.UTF8, "application/json"),
            };
        }

        private async Task<HttpResponseMessage> FinancialAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            FinancialRequests++;
            Assert.True(invoiceBoundary);
            Assert.Equal(HttpMethod.Get, request.Method);
            Assert.Equal("https://capability-accounting.test/internal/invoice-creation/operations/" + Operation.ToString("D")
                + "/financial-ownership", request.RequestUri!.AbsoluteUri);
            Assert.Equal("Bearer", request.Headers.Authorization!.Scheme);
            ValidateOwnMachine(request.Headers.Authorization.Parameter!);
            Assert.False(request.Headers.Contains("X-Maliev-IAM-Live-Check-Key"));
            Assert.True(request.Headers.CacheControl?.NoCache == true);
            Assert.True(request.Headers.CacheControl?.NoStore == true);
            Assert.Null(request.Headers.IfModifiedSince);
            Assert.Empty(request.Headers.IfNoneMatch);
            if (pauseSecondFinancial && FinancialRequests == 2)
            {
                FinancialReached.TrySetResult();
                await FinancialRelease.Task.WaitAsync(cancellationToken);
            }
            return new(financialStatus)
            {
                Content = new StringContent((FinancialRequests == 2 ? SecondFinancialBody : null) ?? financialBody ?? FinancialProof(), System.Text.Encoding.UTF8, "application/json"),
            };
        }

        private sealed class BoundaryFilter(Factory app) : IHttpMessageHandlerBuilderFilter
        {
            public Action<HttpMessageHandlerBuilder> Configure(Action<HttpMessageHandlerBuilder> next) => builder =>
            {
                next(builder);
                if (builder.Name == "LegacyAuthServiceTokenExchange") builder.PrimaryHandler = new BoundaryHandler(app.ExchangeAsync);
                if (builder.Name == "QuotationInvoiceLiveAuthority") builder.PrimaryHandler = new BoundaryHandler(app.IamAsync);
                if (builder.Name == "InvoiceFinancialOwnership") builder.PrimaryHandler = new BoundaryHandler(app.FinancialAsync);
                if (builder.Name == "IAMService") builder.PrimaryHandler = new BoundaryHandler(app.StandardAdmissionAsync);
            };
        }
        // Observe the actual test-client HTTP route before normal Program processes it.
        // Nested real workload login must not overwrite the admitted route. No server
        // service or authorization component is replaced by this client-side observer.
        private sealed class InboundRouteObserver(Factory app) : DelegatingHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                var route = request.RequestUri!.AbsolutePath;
                if (route is Endpoint or "/auth/v1/exchange/invoice-create") app.observedAdmissionRoute = route;
                return base.SendAsync(request, cancellationToken);
            }
        }

        private sealed class BoundaryHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request, cancellationToken);
        }
        public string RemoveQuotationPermission(string token)
        {
            var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
            var claims = jwt.Claims.Where(x => x.Type is not ("iss" or "aud" or "nbf" or "exp")
                && !(x.Type == "permissions" && x.Value == "legacy.quotations.update"));
            return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(jwt.Issuer, jwt.Audiences.Single(), claims,
                DateTime.UtcNow.AddSeconds(-1), DateTime.UtcNow.AddMinutes(10), new SigningCredentials(new RsaSecurityKey(key), SecurityAlgorithms.RsaSha256)));
        }
        public JwtSecurityToken ValidateInvoice(string token)
        {
            new JwtSecurityTokenHandler().ValidateToken(token, new TokenValidationParameters
            {
                ValidIssuer = "https://quotation-capability.test",
                ValidAudience = "legacy-accounting:invoice-create",
                IssuerSigningKey = new RsaSecurityKey(key),
                ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
            }, out var validated);
            return Assert.IsType<JwtSecurityToken>(validated);
        }
        public override async ValueTask DisposeAsync()
        {
            var connections = new List<NpgsqlConnection>();
            try
            {
                await using var scope = Services.CreateAsyncScope();
                var contexts = new DbContext[]
                {
                    scope.ServiceProvider.GetRequiredService<EmployeeIdentityDbContext>(),
                    scope.ServiceProvider.GetRequiredService<CustomerIdentityDbContext>(),
                    scope.ServiceProvider.GetRequiredService<RefreshSessionDbContext>(),
                };
                connections.AddRange(contexts.Select(context => (NpgsqlConnection)context.Database.GetDbConnection()));
                foreach (var context in contexts)
                {
                    await context.Database.OpenConnectionAsync();
                    await context.Database.CloseConnectionAsync();
                }
            }
            finally
            {
                try { await base.DisposeAsync(); }
                finally
                {
                    key.Dispose();
                    foreach (var connection in connections) NpgsqlConnection.ClearPool(connection);
                }
            }
            Assert.True(standardAdmissionFailures == 0,
                "Controlled standard admission assertion failed at: " + string.Join(Environment.NewLine, standardAdmissionFailureSites));
        }
    }

    private sealed class Stores(EmployeeIdentityDbContext employees, CustomerIdentityDbContext customers, RefreshSessionDbContext state) : IAsyncDisposable
    {
        public EmployeeIdentityDbContext Employees { get; } = employees;
        public CustomerIdentityDbContext Customers { get; } = customers;
        public RefreshSessionDbContext State { get; } = state;
        public static async Task<Stores> CreateAsync(PostgresFixture postgres)
        {
            var stores = new Stores(await postgres.CreateEmployeeContextAsync(), await postgres.CreateCustomerContextAsync(), await postgres.CreateStateContextAsync());
            var row = new LegacyIdentityRow
            {
                Id = "capability-employee",
                UserName = "capability@example.test",
                NormalizedUserName = "CAPABILITY@EXAMPLE.TEST",
                Email = "capability@example.test",
                NormalizedEmail = "CAPABILITY@EXAMPLE.TEST",
                EmailConfirmed = true,
                SecurityStamp = "capability-stamp",
                ConcurrencyStamp = "capability-concurrency",
                LockoutEnabled = true,
            };
            row.PasswordHash = new Microsoft.AspNetCore.Identity.PasswordHasher<LegacyIdentityRow>().HashPassword(row, "capability-test-password");
            stores.Employees.Users.Add(row);
            await stores.Employees.SaveChangesAsync();
            return stores;
        }
        public async ValueTask DisposeAsync()
        {
            var connections = new[] { (NpgsqlConnection)Employees.Database.GetDbConnection(), (NpgsqlConnection)Customers.Database.GetDbConnection(), (NpgsqlConnection)State.Database.GetDbConnection() };
            await Employees.DisposeAsync(); await Customers.DisposeAsync(); await State.DisposeAsync();
            foreach (var connection in connections) NpgsqlConnection.ClearPool(connection);
        }
    }
}
