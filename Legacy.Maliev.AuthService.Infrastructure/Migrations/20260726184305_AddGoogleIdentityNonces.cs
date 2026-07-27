using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Legacy.Maliev.AuthService.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddGoogleIdentityNonces : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "google_identity_nonces",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    NonceHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ServiceName = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Application = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_google_identity_nonces", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_google_identity_nonces_ExpiresAt",
                table: "google_identity_nonces",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_google_identity_nonces_NonceHash",
                table: "google_identity_nonces",
                column: "NonceHash",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "google_identity_nonces");
        }
    }
}
