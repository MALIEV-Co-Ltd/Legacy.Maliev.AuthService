using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Legacy.Maliev.AuthService.Infrastructure.Migrations.CustomerIdentityPostgres;

/// <summary>Adds explicit customer password-setup lifecycle state without classifying existing credentials heuristically.</summary>
[DbContext(typeof(CustomerIdentityDbContext))]
[Migration("202609070001_AddCustomerPasswordSetupLifecycle")]
public sealed class AddCustomerPasswordSetupLifecycle : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder) =>
        migrationBuilder.AddColumn<bool>(
            name: "PasswordSetupRequired",
            table: "AspNetUsers",
            type: "boolean",
            nullable: false,
            defaultValue: false);

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder) =>
        migrationBuilder.DropColumn(
            name: "PasswordSetupRequired",
            table: "AspNetUsers");
}
