using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Legacy.Maliev.AuthService.Infrastructure.Migrations.CustomerIdentityPostgres;

/// <summary>Restores the inherited customer Identity persistence tables without modifying users.</summary>
[DbContext(typeof(CustomerIdentityDbContext))]
[Migration("202610100001_RestoreCustomerIdentityAncillaryStore")]
public sealed class RestoreCustomerIdentityAncillaryStore : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder) =>
        LegacyIdentityAncillarySchema.Create(migrationBuilder, includeTokens: true);

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder) => throw new NotSupportedException(
        "Original Identity claims, logins, roles and tokens may contain persistent account state and must be retained.");
}
