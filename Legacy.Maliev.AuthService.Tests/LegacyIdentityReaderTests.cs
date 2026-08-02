using Legacy.Maliev.AuthService.Domain;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Time.Testing;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class LegacyIdentityReaderTests(PostgresFixture postgres)
{
    private static readonly DateTimeOffset Now = new(2026, 7, 15, 0, 0, 0, TimeSpan.Zero);

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

    [Fact]
    public async Task Validate_LegacyIssuedCustomerPassword_RequiresInitialPasswordWithoutAffectingEmployees()
    {
        var temporaryPassword = LegacyIssuedCredential;
        await using var contexts = await ContextPair.CreateAsync(postgres);
        var customer = CreateUser("customer-id", "customer@example.com", temporaryPassword);
        customer.DatabaseID = 42;
        customer.EmailConfirmed = true;
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

    [Fact]
    public async Task ContextModels_MapCustomerOnlyColumnsOnlyInCustomerDatabase()
    {
        await using var contexts = await ContextPair.CreateAsync(postgres);

        var customer = contexts.Customer.Model.FindEntityType(typeof(LegacyIdentityRow));
        var employee = contexts.Employee.Model.FindEntityType(typeof(LegacyIdentityRow));

        Assert.NotNull(customer?.FindProperty(nameof(LegacyIdentityRow.FaxNumber)));
        Assert.NotNull(customer?.FindProperty(nameof(LegacyIdentityRow.MobileNumber)));
        Assert.Null(employee?.FindProperty(nameof(LegacyIdentityRow.FaxNumber)));
        Assert.Null(employee?.FindProperty(nameof(LegacyIdentityRow.MobileNumber)));
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
