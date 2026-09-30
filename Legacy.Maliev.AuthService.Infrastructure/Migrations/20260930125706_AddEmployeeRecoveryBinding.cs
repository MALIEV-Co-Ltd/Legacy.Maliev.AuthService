using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Legacy.Maliev.AuthService.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddEmployeeRecoveryBinding : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "BoundNormalizedEmail",
                table: "identity_action_tokens",
                type: "character varying(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "BoundSecurityStamp",
                table: "identity_action_tokens",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "EffectActionId",
                table: "identity_action_tokens",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "FinalizedAt",
                table: "identity_action_tokens",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "OriginalTokenSha256",
                table: "identity_action_tokens",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "OwnerSubject",
                table: "identity_action_tokens",
                type: "character varying(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "RecoveryVersion",
                table: "identity_action_tokens",
                type: "integer",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_identity_action_tokens_OriginalTokenSha256_Purpose",
                table: "identity_action_tokens",
                columns: new[] { "OriginalTokenSha256", "Purpose" },
                unique: true);

            migrationBuilder.AddCheckConstraint(
                name: "CK_identity_action_tokens_employee_binding",
                table: "identity_action_tokens",
                sql: "\"RecoveryVersion\" IS NULL OR (\"RecoveryVersion\" = 1 AND \"Purpose\" IN ('employee-password-reset', 'employee-email-confirmation') AND \"OriginalTokenSha256\" IS NOT NULL AND length(\"OriginalTokenSha256\") = 64 AND \"OwnerSubject\" IS NOT NULL AND length(\"OwnerSubject\") > 0 AND \"BoundNormalizedEmail\" IS NOT NULL AND length(\"BoundNormalizedEmail\") > 0 AND \"BoundSecurityStamp\" IS NOT NULL AND length(\"BoundSecurityStamp\") > 0)");

            migrationBuilder.AddCheckConstraint(
                name: "CK_identity_action_tokens_employee_finalization",
                table: "identity_action_tokens",
                sql: "(\"FinalizedAt\" IS NULL AND \"EffectActionId\" IS NULL) OR (\"RecoveryVersion\" IS NOT NULL AND \"RecoveryVersion\" = 1 AND \"FinalizedAt\" IS NOT NULL AND \"ConsumedAt\" IS NOT NULL AND \"EffectActionId\" IS NOT NULL AND \"EffectActionId\" = \"Id\")");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_identity_action_tokens_OriginalTokenSha256_Purpose",
                table: "identity_action_tokens");

            migrationBuilder.DropCheckConstraint(
                name: "CK_identity_action_tokens_employee_binding",
                table: "identity_action_tokens");

            migrationBuilder.DropCheckConstraint(
                name: "CK_identity_action_tokens_employee_finalization",
                table: "identity_action_tokens");

            migrationBuilder.DropColumn(
                name: "BoundNormalizedEmail",
                table: "identity_action_tokens");

            migrationBuilder.DropColumn(
                name: "BoundSecurityStamp",
                table: "identity_action_tokens");

            migrationBuilder.DropColumn(
                name: "EffectActionId",
                table: "identity_action_tokens");

            migrationBuilder.DropColumn(
                name: "FinalizedAt",
                table: "identity_action_tokens");

            migrationBuilder.DropColumn(
                name: "OriginalTokenSha256",
                table: "identity_action_tokens");

            migrationBuilder.DropColumn(
                name: "OwnerSubject",
                table: "identity_action_tokens");

            migrationBuilder.DropColumn(
                name: "RecoveryVersion",
                table: "identity_action_tokens");
        }
    }
}
