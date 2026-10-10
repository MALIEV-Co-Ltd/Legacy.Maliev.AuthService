using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Legacy.Maliev.AuthService.Infrastructure.Migrations.EmployeeIdentityPostgres;

/// <summary>Restores employee Identity tables alongside the separately reviewed authenticator token store.</summary>
[DbContext(typeof(EmployeeIdentityDbContext))]
[Migration("202610100001_RestoreEmployeeIdentityAncillaryStore")]
public sealed class RestoreEmployeeIdentityAncillaryStore : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        LegacyIdentityAncillarySchema.ValidateEmployeeTokenStore(migrationBuilder);
        LegacyIdentityAncillarySchema.Create(migrationBuilder, includeTokens: false);
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder) => throw new NotSupportedException(
        "Original Identity claims, logins and roles may contain persistent account state and must be retained.");
}
