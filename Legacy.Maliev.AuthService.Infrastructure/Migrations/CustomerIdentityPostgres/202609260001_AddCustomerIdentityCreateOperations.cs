using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Legacy.Maliev.AuthService.Infrastructure.Migrations.CustomerIdentityPostgres;

/// <summary>Adds atomic, service-owned operation receipts for keyed identity creation.</summary>
[DbContext(typeof(CustomerIdentityDbContext))]
[Migration("202609260001_AddCustomerIdentityCreateOperations")]
public sealed class AddCustomerIdentityCreateOperations : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "CustomerIdentityCreateOperations",
            columns: table => new
            {
                Id = table.Column<long>(type: "bigint", nullable: false)
                    .Annotation("Npgsql:ValueGenerationStrategy", Npgsql.EntityFrameworkCore.PostgreSQL.Metadata.NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                ServiceSubject = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                OperationKey = table.Column<Guid>(type: "uuid", nullable: false),
                DatabaseId = table.Column<int>(type: "integer", nullable: false),
                IdentityId = table.Column<string>(type: "character varying(450)", maxLength: 450, nullable: false),
                PayloadSalt = table.Column<byte[]>(type: "bytea", maxLength: 16, nullable: false),
                PayloadHash = table.Column<byte[]>(type: "bytea", maxLength: 32, nullable: false),
            },
            constraints: table => table.PrimaryKey("PK_CustomerIdentityCreateOperations", x => x.Id));

        migrationBuilder.CreateIndex(
            name: "IX_CustomerIdentityCreateOperations_ServiceSubject_OperationKey",
            table: "CustomerIdentityCreateOperations",
            columns: new[] { "ServiceSubject", "OperationKey" },
            unique: true);
        migrationBuilder.CreateIndex(
            name: "IX_CustomerIdentityCreateOperations_DatabaseId",
            table: "CustomerIdentityCreateOperations",
            column: "DatabaseId",
            unique: true);
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder) =>
        migrationBuilder.DropTable(name: "CustomerIdentityCreateOperations");
}
