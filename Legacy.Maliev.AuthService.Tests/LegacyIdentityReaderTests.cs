using Legacy.Maliev.AuthService.Domain;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Time.Testing;

namespace Legacy.Maliev.AuthService.Tests;

/// <summary>
/// Exercises legacy password validation, lifecycle eligibility, and isolated customer and employee model mappings.
/// </summary>
/// <param name="postgres">The collection-owned fixture that creates isolated PostgreSQL stores for each case.</param>
[Collection(PostgresCollection.Name)]
public sealed class LegacyIdentityReaderTests(PostgresFixture postgres)
{
    private static readonly DateTimeOffset Now = new(2026, 7, 15, 0, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// Checks that an identity ID is not accepted as the employee's password.
    /// </summary>
    /// <returns>A task that completes when the asynchronous assertions finish.</returns>
    [Fact]
    public async Task Validate_ExistingIdentityIdUsedAsPassword_IsRejected()
    {
        await using var contexts = await ContextPair.CreateAsync(postgres);
        var user = CreateUser("legacy-id", "employee@maliev.com", "real-password");
        contexts.Employee.Users.Add(user);
        await contexts.Employee.SaveChangesAsync();
        var reader = contexts.CreateReader();

        var result = await reader.ValidateAsync(
            "employee@maliev.com", "legacy-id", IdentityKind.Employee, default);

        Assert.Null(result);
    }

    /// <summary>
    /// Checks that a valid legacy password projects the linked customer identity and lifecycle flags.
    /// </summary>
    /// <returns>A task that completes when the asynchronous assertions finish.</returns>
    [Fact]
    public async Task Validate_CorrectAspNetIdentityPassword_ReturnsProjectedIdentity()
    {
        await using var contexts = await ContextPair.CreateAsync(postgres);
        var user = CreateUser("legacy-id", "customer@example.com", "correct-password");
        user.DatabaseID = 42;
        user.EmailConfirmed = true;
        contexts.Customer.Users.Add(user);
        await contexts.Customer.SaveChangesAsync();
        var reader = contexts.CreateReader();

        var result = await reader.ValidateAsync(
            "customer@example.com", "correct-password", IdentityKind.Customer, default);

        Assert.NotNull(result);
        Assert.Equal("legacy-id", result.Id);
        Assert.Equal(42, result.DatabaseId);
        Assert.Equal(IdentityKind.Customer, result.Kind);
        Assert.True(result.EmailConfirmed);
        Assert.False(result.RequiresInitialPassword);
    }

    /// <summary>
    /// Checks that explicit customer bootstrap state does not impose password setup on employees.
    /// </summary>
    /// <returns>A task that completes when the asynchronous assertions finish.</returns>
    [Fact]
    public async Task Validate_ExplicitCustomerLifecycle_RequiresInitialPasswordWithoutAffectingEmployees()
    {
        var temporaryPassword = LegacyIssuedCredential;
        await using var contexts = await ContextPair.CreateAsync(postgres);
        var customer = CreateUser("customer-id", "customer@example.com", temporaryPassword);
        customer.DatabaseID = 42;
        customer.EmailConfirmed = true;
        customer.PasswordSetupRequired = true;
        var employee = CreateUser("employee-id", "employee@maliev.com", temporaryPassword);
        contexts.Customer.Users.Add(customer);
        contexts.Employee.Users.Add(employee);
        await contexts.Customer.SaveChangesAsync();
        await contexts.Employee.SaveChangesAsync();
        var reader = contexts.CreateReader();

        var customerResult = await reader.ValidateAsync(
            customer.Email!, temporaryPassword, IdentityKind.Customer, default);
        var employeeResult = await reader.ValidateAsync(
            employee.Email!, temporaryPassword, IdentityKind.Employee, default);

        Assert.True(customerResult?.RequiresInitialPassword);
        Assert.False(employeeResult?.RequiresInitialPassword);
    }

    /// <summary>
    /// Checks that a customer-owned password matching an old heuristic does not re-enable bootstrap setup.
    /// </summary>
    /// <returns>A task that completes when the asynchronous assertions finish.</returns>
    [Fact]
    public async Task Validate_CustomerOwnedPasswordMatchingOldHeuristic_DoesNotRetriggerSetup()
    {
        await using var contexts = await ContextPair.CreateAsync(postgres);
        var customer = CreateUser("customer-id", "customer@example.com", LegacyIssuedCredential);
        customer.DatabaseID = 42;
        customer.EmailConfirmed = true;
        customer.PasswordSetupRequired = false;
        contexts.Customer.Users.Add(customer);
        await contexts.Customer.SaveChangesAsync();

        var result = await contexts.CreateReader().ValidateAsync(
            customer.Email!, LegacyIssuedCredential, IdentityKind.Customer, default);

        Assert.NotNull(result);
        Assert.False(result.RequiresInitialPassword);
    }

    /// <summary>
    /// Checks that current lockout rejects an otherwise correct password.
    /// </summary>
    /// <returns>A task that completes when the asynchronous assertions finish.</returns>
    [Fact]
    public async Task Validate_LockedIdentity_IsRejectedEvenWithCorrectPassword()
    {
        await using var contexts = await ContextPair.CreateAsync(postgres);
        var user = CreateUser("legacy-id", "locked@maliev.com", "correct-password");
        user.LockoutEnabled = true;
        user.LockoutEnd = Now.AddMinutes(10);
        contexts.Employee.Users.Add(user);
        await contexts.Employee.SaveChangesAsync();
        var reader = contexts.CreateReader();

        var result = await reader.ValidateAsync(
            "locked@maliev.com", "correct-password", IdentityKind.Employee, default);

        Assert.Null(result);
    }

    /// <summary>
    /// Checks that password validation preserves an unconfirmed customer's recovery eligibility.
    /// </summary>
    /// <returns>A task that completes when the asynchronous assertions finish.</returns>
    [Fact]
    public async Task Validate_UnconfirmedCustomer_ReturnsRecoveryEligibleIdentityWithoutSessionEligibility()
    {
        await using var contexts = await ContextPair.CreateAsync(postgres);
        var user = CreateUser("legacy-id", "unconfirmed@example.com", "correct-password");
        user.EmailConfirmed = false;
        contexts.Customer.Users.Add(user);
        await contexts.Customer.SaveChangesAsync();
        var reader = contexts.CreateReader();

        var result = await reader.ValidateAsync(
            "unconfirmed@example.com", "correct-password", IdentityKind.Customer, default);

        Assert.NotNull(result);
        Assert.False(result.EmailConfirmed);
    }

    /// <summary>
    /// Checks that an unconfirmed customer cannot satisfy active-session lookup.
    /// </summary>
    /// <returns>A task that completes when the asynchronous assertions finish.</returns>
    [Fact]
    public async Task FindActive_UnconfirmedCustomer_IsRejectedForRefreshValidation()
    {
        await using var contexts = await ContextPair.CreateAsync(postgres);
        var user = CreateUser("legacy-id", "unconfirmed@example.com", "correct-password");
        user.EmailConfirmed = false;
        contexts.Customer.Users.Add(user);
        await contexts.Customer.SaveChangesAsync();
        var reader = contexts.CreateReader();

        var result = await reader.FindActiveAsync("legacy-id", IdentityKind.Customer, default);

        Assert.Null(result);
    }

    /// <summary>
    /// Checks that an unconfirmed employee's password result retains its flag while active-session lookups reject it.
    /// </summary>
    /// <returns>A task that completes when the asynchronous assertions finish.</returns>
    [Fact]
    public async Task UnconfirmedEmployee_PasswordValidationPreservesFlagButActiveSessionLookupsRejectIt()
    {
        await using var contexts = await ContextPair.CreateAsync(postgres);
        var user = CreateUser("employee-id", "unconfirmed@maliev.com", "correct-password");
        user.EmailConfirmed = false;
        contexts.Employee.Users.Add(user);
        await contexts.Employee.SaveChangesAsync();
        var reader = contexts.CreateReader();

        var validated = await reader.ValidateAsync(
            user.UserName!, "correct-password", IdentityKind.Employee, default);
        var activeById = await reader.FindActiveAsync(user.Id, IdentityKind.Employee, default);
        var activeByEmail = await reader.FindActiveEmployeeByEmailAsync(user.Email!, default);

        Assert.NotNull(validated);
        Assert.False(validated.EmailConfirmed);
        Assert.Null(activeById);
        Assert.Null(activeByEmail);
    }

    /// <summary>
    /// Checks confirmed employee lookup by both identity ID and email.
    /// </summary>
    /// <returns>A task that completes when the asynchronous assertions finish.</returns>
    [Fact]
    public async Task ConfirmedEmployee_RemainsEligibleForSessionLookups()
    {
        await using var contexts = await ContextPair.CreateAsync(postgres);
        var user = CreateUser("employee-id", "confirmed@maliev.com", "correct-password");
        contexts.Employee.Users.Add(user);
        await contexts.Employee.SaveChangesAsync();
        var reader = contexts.CreateReader();

        Assert.NotNull(await reader.FindActiveAsync(user.Id, IdentityKind.Employee, default));
        Assert.NotNull(await reader.FindActiveEmployeeByEmailAsync(user.Email!, default));
    }

    /// <summary>
    /// Checks that fax, mobile, and bootstrap properties map only in the customer identity database.
    /// </summary>
    /// <returns>A task that completes when the asynchronous assertions finish.</returns>
    [Fact]
    public async Task ContextModels_MapCustomerOnlyColumnsOnlyInCustomerDatabase()
    {
        await using var contexts = await ContextPair.CreateAsync(postgres);

        var customer = contexts.Customer.Model.FindEntityType(typeof(LegacyIdentityRow));
        var employee = contexts.Employee.Model.FindEntityType(typeof(LegacyIdentityRow));

        Assert.NotNull(customer?.FindProperty(nameof(LegacyIdentityRow.FaxNumber)));
        Assert.NotNull(customer?.FindProperty(nameof(LegacyIdentityRow.MobileNumber)));
        Assert.NotNull(customer?.FindProperty(nameof(LegacyIdentityRow.PasswordSetupRequired)));
        Assert.Null(employee?.FindProperty(nameof(LegacyIdentityRow.FaxNumber)));
        Assert.Null(employee?.FindProperty(nameof(LegacyIdentityRow.MobileNumber)));
        Assert.Null(employee?.FindProperty(nameof(LegacyIdentityRow.PasswordSetupRequired)));
    }

    private static string LegacyIssuedCredential =>
        string.Concat("Abcd", "EFgh", "2345", "!@$%", "JKLM");

    private static LegacyIdentityRow CreateUser(string id, string email, string password)
    {
        var user = new LegacyIdentityRow
        {
            Id = id,
            UserName = email,
            NormalizedUserName = email.ToUpperInvariant(),
            Email = email,
            NormalizedEmail = email.ToUpperInvariant(),
            EmailConfirmed = true,
            SecurityStamp = "security-stamp",
        };
        user.PasswordHash = new PasswordHasher<LegacyIdentityRow>().HashPassword(user, password);
        return user;
    }

    private sealed class ContextPair : IAsyncDisposable
    {
        private ContextPair(CustomerIdentityDbContext customer, EmployeeIdentityDbContext employee)
        {
            Customer = customer;
            Employee = employee;
        }

        public CustomerIdentityDbContext Customer { get; }

        public EmployeeIdentityDbContext Employee { get; }

        public static async Task<ContextPair> CreateAsync(PostgresFixture postgres)
        {
            var customer = await postgres.CreateCustomerContextAsync();
            var employee = await postgres.CreateEmployeeContextAsync();
            return new(customer, employee);
        }

        public LegacyIdentityReader CreateReader() => new(
            Customer,
            Employee,
            new PasswordHasher<LegacyIdentityRow>(),
            new FakeTimeProvider(Now));

        public async ValueTask DisposeAsync()
        {
            await Customer.DisposeAsync();
            await Employee.DisposeAsync();
        }
    }
}
