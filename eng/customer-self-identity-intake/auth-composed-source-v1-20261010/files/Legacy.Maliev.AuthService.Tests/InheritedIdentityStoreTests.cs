using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql;
using System.Text.Json;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class InheritedIdentityStoreModelTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void BothModels_PreserveOriginalKeysRelationshipsAndRoleConcurrency(bool employee)
    {
        using LegacyIdentityDbContext context = employee
            ? new EmployeeIdentityDbContext(new DbContextOptionsBuilder<EmployeeIdentityDbContext>().UseNpgsql("Host=localhost;Database=model_only").Options)
            : new CustomerIdentityDbContext(new DbContextOptionsBuilder<CustomerIdentityDbContext>().UseNpgsql("Host=localhost;Database=model_only").Options);
        var expected = new (Type Type, string Table, string[] Key)[]
        {
            (typeof(IdentityRole), "AspNetRoles", ["Id"]),
            (typeof(IdentityRoleClaim<string>), "AspNetRoleClaims", ["Id"]),
            (typeof(IdentityUserClaim<string>), "AspNetUserClaims", ["Id"]),
            (typeof(IdentityUserLogin<string>), "AspNetUserLogins", ["LoginProvider", "ProviderKey"]),
            (typeof(IdentityUserRole<string>), "AspNetUserRoles", ["UserId", "RoleId"]),
            (typeof(IdentityUserToken<string>), "AspNetUserTokens", ["UserId", "LoginProvider", "Name"]),
        };
        foreach (var item in expected)
        {
            var entity = context.Model.FindEntityType(item.Type)!;
            Assert.NotNull(entity);
            Assert.Equal(item.Table, entity.GetTableName());
            Assert.Equal(item.Key, entity.FindPrimaryKey()!.Properties.Select(property => property.Name));
            Assert.All(entity.GetForeignKeys(), foreignKey => Assert.Equal(DeleteBehavior.Cascade, foreignKey.DeleteBehavior));
        }
        Assert.Equal(6, expected.Sum(item => context.Model.FindEntityType(item.Type)!.GetForeignKeys().Count()));
        var role = context.Model.FindEntityType(typeof(IdentityRole))!;
        Assert.True(role.FindProperty("ConcurrencyStamp")!.IsConcurrencyToken);
        Assert.Equal(256, role.FindProperty("NormalizedName")!.GetMaxLength());
        var index = Assert.Single(role.GetIndexes());
        Assert.True(index.IsUnique);
        Assert.Equal("RoleNameIndex", index.GetDatabaseName());
        Assert.DoesNotContain(context.Model.GetEntityTypes().SelectMany(entity => entity.GetProperties()), property => property.Name == "xmin");
        var user = context.Model.FindEntityType(typeof(LegacyIdentityRow))!;
        Assert.Equal(employee, user.FindProperty("FaxNumber") is null);
        Assert.Equal(employee, user.FindProperty("MobileNumber") is null);
    }

    [Fact]
    public void AdministrativeWireProjections_DoNotExposeInheritedStoreOrTokenMaterial()
    {
        var forbidden = new[] { "Roles", "Claims", "Logins", "Tokens", "PasswordHash", "SecurityStamp", "AuthenticatorKey", "Value" };
        foreach (var type in new[] { typeof(CustomerIdentityResponse), typeof(EmployeeIdentityResponse) })
        {
            // Exercise the actual serializer's configured default contract, including ignored properties.
            var contract = new JsonSerializerOptions(JsonSerializerDefaults.Web)
            {
                TypeInfoResolver = new System.Text.Json.Serialization.Metadata.DefaultJsonTypeInfoResolver(),
            }.GetTypeInfo(type);
            Assert.DoesNotContain(contract.Properties, property => forbidden.Contains(property.Name, StringComparer.OrdinalIgnoreCase));
        }
    }
}

[Collection(PostgresCollection.Name)]
public sealed class InheritedIdentityStorePersistenceTests(PostgresFixture postgres)
{
    [Theory]
    [InlineData("ALTER TABLE \"AspNetUserTokens\" ADD COLUMN \"Unexpected\" text NULL")]
    [InlineData("ALTER TABLE \"AspNetUserTokens\" DROP CONSTRAINT \"PK_AspNetUserTokens\"; ALTER TABLE \"AspNetUserTokens\" ADD PRIMARY KEY (\"Name\", \"UserId\", \"LoginProvider\")")]
    [InlineData("ALTER TABLE \"AspNetUserTokens\" DROP CONSTRAINT \"FK_AspNetUserTokens_AspNetUsers_UserId\"; ALTER TABLE \"AspNetUserTokens\" ADD FOREIGN KEY (\"UserId\") REFERENCES \"AspNetUsers\" (\"Id\") ON DELETE RESTRICT")]
    [InlineData("ALTER TABLE \"AspNetUserTokens\" DROP CONSTRAINT \"FK_AspNetUserTokens_AspNetUsers_UserId\"; ALTER TABLE \"AspNetUserTokens\" ADD FOREIGN KEY (\"UserId\") REFERENCES \"AspNetUsers\" (\"Id\") ON DELETE CASCADE NOT VALID")]
    public async Task EmployeeUpgrade_RejectsWrongExistingTokenStoreBeforeAddingAncillaryTables(string corruptShapeSql)
    {
        await using var context = new EmployeeIdentityDbContext(new DbContextOptionsBuilder<EmployeeIdentityDbContext>()
            .UseNpgsql(await postgres.CreateDatabaseAsync()).Options);
        await context.GetService<IMigrator>().MigrateAsync("202610090001_RestoreEmployeeIdentityTokenStore");
        context.Users.Add(new() { Id = "retained-owner", DatabaseID = 9 });
        await context.SaveChangesAsync();
        await context.Database.ExecuteSqlRawAsync(corruptShapeSql);
        var failure = await Assert.ThrowsAsync<PostgresException>(() => context.Database.MigrateAsync());
        Assert.Contains("Employee Identity token-store", failure.MessageText);
        Assert.Equal("retained-owner", (await context.Users.SingleAsync()).Id);
        var tables = await context.Database.SqlQueryRaw<string>(
            "SELECT table_name AS \"Value\" FROM information_schema.tables WHERE table_schema = 'public'").ToListAsync();
        Assert.DoesNotContain("AspNetRoles", tables);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MigratedStores_RoundtripOriginalAncillaryValuesAndCascadeOnlyOwnedRows(bool employee)
    {
        await using LegacyIdentityDbContext context = employee
            ? await postgres.CreateEmployeeContextAsync()
            : await postgres.CreateCustomerContextAsync();
        var owner = new LegacyIdentityRow { Id = "owner", UserName = "owner@maliev.com", DatabaseID = 7 };
        var survivor = new LegacyIdentityRow { Id = "survivor", UserName = "survivor@maliev.com", DatabaseID = 8 };
        var role = new IdentityRole { Id = "role", Name = "SourceRole", NormalizedName = "SOURCEROLE", ConcurrencyStamp = "original-stamp" };
        context.Users.AddRange(owner, survivor);
        context.Set<IdentityRole>().Add(role);
        await context.SaveChangesAsync();
        context.Set<IdentityRoleClaim<string>>().Add(new() { RoleId = role.Id, ClaimType = "source-role-claim", ClaimValue = null });
        context.Set<IdentityUserClaim<string>>().Add(new() { UserId = owner.Id, ClaimType = "maliev:credential_state", ClaimValue = "temporary_password" });
        context.Set<IdentityUserClaim<string>>().Add(new() { UserId = survivor.Id, ClaimType = "surviving-claim", ClaimValue = "ผู้ใช้" });
        context.Set<IdentityUserLogin<string>>().Add(new() { UserId = owner.Id, LoginProvider = "original-provider", ProviderKey = "original-key", ProviderDisplayName = null });
        context.Set<IdentityUserRole<string>>().Add(new() { UserId = owner.Id, RoleId = role.Id });
        context.Set<IdentityUserToken<string>>().Add(new() { UserId = owner.Id, LoginProvider = "[AspNetUserStore]", Name = "AuthenticatorKey", Value = "synthetic-key" });
        await context.SaveChangesAsync();
        context.ChangeTracker.Clear();

        Assert.Null((await context.Set<IdentityRoleClaim<string>>().SingleAsync()).ClaimValue);
        Assert.Equal("temporary_password", (await context.Set<IdentityUserClaim<string>>().SingleAsync(value => value.UserId == "owner")).ClaimValue);
        Assert.Null((await context.Set<IdentityUserLogin<string>>().SingleAsync()).ProviderDisplayName);
        Assert.Equal("original-key", (await context.Set<IdentityUserLogin<string>>().SingleAsync()).ProviderKey);
        Assert.Equal("synthetic-key", (await context.Set<IdentityUserToken<string>>().SingleAsync()).Value);
        Assert.Equal("role", (await context.Set<IdentityUserRole<string>>().SingleAsync()).RoleId);
        Assert.Equal("original-stamp", (await context.Set<IdentityRole>().SingleAsync()).ConcurrencyStamp);

        context.ChangeTracker.Clear();
        context.Set<IdentityRole>().Add(new() { Id = "duplicate-role", NormalizedName = "SOURCEROLE" });
        var duplicateRole = await Assert.ThrowsAsync<DbUpdateException>(() => context.SaveChangesAsync());
        Assert.Equal(PostgresErrorCodes.UniqueViolation, Assert.IsType<PostgresException>(duplicateRole.InnerException).SqlState);
        context.ChangeTracker.Clear();
        context.Set<IdentityUserLogin<string>>().Add(new() { UserId = survivor.Id, LoginProvider = "original-provider", ProviderKey = "original-key" });
        var duplicateLogin = await Assert.ThrowsAsync<DbUpdateException>(() => context.SaveChangesAsync());
        Assert.Equal(PostgresErrorCodes.UniqueViolation, Assert.IsType<PostgresException>(duplicateLogin.InnerException).SqlState);

        // Clear tracked dependents so PostgreSQL, rather than client-side cascade, proves the constraints.
        context.ChangeTracker.Clear();
        context.Users.Remove(await context.Users.SingleAsync(value => value.Id == "owner"));
        await context.SaveChangesAsync();
        Assert.Empty(await context.Set<IdentityUserLogin<string>>().ToListAsync());
        Assert.Empty(await context.Set<IdentityUserRole<string>>().ToListAsync());
        Assert.Empty(await context.Set<IdentityUserToken<string>>().ToListAsync());
        Assert.Equal("ผู้ใช้", (await context.Set<IdentityUserClaim<string>>().SingleAsync()).ClaimValue);
        Assert.Single(await context.Set<IdentityRoleClaim<string>>().ToListAsync());

        context.ChangeTracker.Clear();
        context.Set<IdentityRole>().Remove(await context.Set<IdentityRole>().SingleAsync());
        await context.SaveChangesAsync();
        Assert.Empty(await context.Set<IdentityRoleClaim<string>>().ToListAsync());
        Assert.Equal("survivor", (await context.Users.SingleAsync()).Id);
    }
}
