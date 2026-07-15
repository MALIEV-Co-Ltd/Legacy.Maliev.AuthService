using Microsoft.EntityFrameworkCore.Migrations;
using System;

#nullable disable

namespace Legacy.Maliev.AuthService.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddIdentityActionTokens : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "identity_action_tokens",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    IdentityId = table.Column<string>(type: "character varying(450)", maxLength: 450, nullable: false),
                    TokenHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Purpose = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ConsumedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_identity_action_tokens", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_identity_action_tokens_ExpiresAt",
                table: "identity_action_tokens",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_identity_action_tokens_IdentityId_Purpose_TokenHash",
                table: "identity_action_tokens",
                columns: new[] { "IdentityId", "Purpose", "TokenHash" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "identity_action_tokens");
        }
    }
}