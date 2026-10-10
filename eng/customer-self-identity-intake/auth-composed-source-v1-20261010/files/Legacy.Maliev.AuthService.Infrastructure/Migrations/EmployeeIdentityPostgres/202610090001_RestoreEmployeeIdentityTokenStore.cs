using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Legacy.Maliev.AuthService.Infrastructure.Migrations.EmployeeIdentityPostgres;

/// <summary>Restores the original employee Identity token table without changing user rows.</summary>
[DbContext(typeof(EmployeeIdentityDbContext))]
[Migration("202610090001_RestoreEmployeeIdentityTokenStore")]
public sealed class RestoreEmployeeIdentityTokenStore : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("""
        CREATE TABLE IF NOT EXISTS "AspNetUserTokens" (
            "UserId" character varying(450) NOT NULL,
            "LoginProvider" text NOT NULL,
            "Name" text NOT NULL,
            "Value" text NULL,
            CONSTRAINT "PK_AspNetUserTokens" PRIMARY KEY ("UserId", "LoginProvider", "Name"),
            CONSTRAINT "FK_AspNetUserTokens_AspNetUsers_UserId" FOREIGN KEY ("UserId") REFERENCES "AspNetUsers" ("Id") ON DELETE CASCADE
        );
        """);

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder) => throw new NotSupportedException(
        "The original employee token store can contain persisted authenticator enrollment and must be retained.");
}
