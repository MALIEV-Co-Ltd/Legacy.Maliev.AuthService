using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Legacy.Maliev.AuthService.Infrastructure.Migrations.EmployeeIdentityPostgres;

/// <summary>Additive identity-effect receipts; reviewed deployment requires an old-writer drain.</summary>
[DbContext(typeof(EmployeeIdentityDbContext))]
[Migration("202609300001_AddEmployeeRecoveryEffects")]
public sealed class AddEmployeeRecoveryEffects : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable("EmployeeRecoveryEffects", columns: table => new
        {
            ActionId = table.Column<Guid>(type: "uuid", nullable: false),
            TokenSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
            Purpose = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
            OwnerSubject = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
            IdentityId = table.Column<string>(type: "character varying(450)", maxLength: 450, nullable: false),
            NormalizedEmail = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
            BeforeSecurityStamp = table.Column<string>(type: "text", nullable: false),
            AfterSecurityStamp = table.Column<string>(type: "text", nullable: false),
            AfterConcurrencyStamp = table.Column<string>(type: "text", nullable: false),
            PasswordPayloadHash = table.Column<string>(type: "text", nullable: true),
            AppliedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
            FinalizedAcknowledgedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
        }, constraints: table =>
        {
            table.PrimaryKey("PK_EmployeeRecoveryEffects", x => x.ActionId);
            table.CheckConstraint("CK_EmployeeRecoveryEffects_PurposePayload", "(\"Purpose\" = 'employee-password-reset' AND \"PasswordPayloadHash\" IS NOT NULL) OR (\"Purpose\" = 'employee-email-confirmation' AND \"PasswordPayloadHash\" IS NULL)");
            table.CheckConstraint("CK_EmployeeRecoveryEffects_Binding", "length(\"TokenSha256\") = 64 AND length(\"OwnerSubject\") > 0 AND length(\"BeforeSecurityStamp\") > 0 AND length(\"AfterSecurityStamp\") > 0");
        });
        migrationBuilder.CreateIndex("IX_EmployeeRecoveryEffects_TokenSha256_Purpose", "EmployeeRecoveryEffects", new[] { "TokenSha256", "Purpose" }, unique: true);
        migrationBuilder.CreateIndex("IX_EmployeeRecoveryEffects_IdentityId_FinalizedAcknowledgedAt", "EmployeeRecoveryEffects", new[] { "IdentityId", "FinalizedAcknowledgedAt" });
        migrationBuilder.CreateIndex("IX_EmployeeRecoveryEffects_FinalizedAcknowledgedAt_AppliedAt", "EmployeeRecoveryEffects", new[] { "FinalizedAcknowledgedAt", "AppliedAt" });
    }

    protected override void Down(MigrationBuilder migrationBuilder) => migrationBuilder.DropTable("EmployeeRecoveryEffects");
}
