using Microsoft.EntityFrameworkCore.Migrations;
using System;

#nullable disable

namespace Legacy.Maliev.AuthService.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class InitialRefreshSessions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "refresh_sessions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    FamilyId = table.Column<Guid>(type: "uuid", nullable: false),
                    IdentityId = table.Column<string>(type: "character varying(450)", maxLength: 450, nullable: false),
                    IdentityKind = table.Column<int>(type: "integer", nullable: false),
                    SecurityStamp = table.Column<string>(type: "text", nullable: true),
                    TokenHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    RotatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    RevokedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    ReplacedById = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_refresh_sessions", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_refresh_sessions_ExpiresAt",
                table: "refresh_sessions",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_refresh_sessions_FamilyId",
                table: "refresh_sessions",
                column: "FamilyId");

            migrationBuilder.CreateIndex(
                name: "IX_refresh_sessions_TokenHash",
                table: "refresh_sessions",
                column: "TokenHash",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "refresh_sessions");
        }
    }
}