using System.Xml;
using Legacy.Maliev.AuthService.Infrastructure;
using Npgsql;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class EmployeeDataProtectionPostgresTests(PostgresFixture postgres)
{
    [Fact]
    public async Task ProtectedRing_OriginalSchemaAndEncryptedKeysRoundtripWithoutPersistentConnections()
    {
        await using var ring = await EmployeeRememberedKeyRingFixture.CreateAsync(postgres);
        var connection = new NpgsqlConnectionStringBuilder(ring.Settings["ConnectionStrings:employee-data-protection"]!) { Pooling = false }.ConnectionString;
        var repository = new EmployeeDataProtectionXmlRepository(connection);
        var original = repository.GetAllElements().Select(element => element.ToString()).ToArray();
        Assert.Single(original);
        Assert.Contains("encryptedSecret", original[0], StringComparison.Ordinal);
        Assert.DoesNotContain("<masterKey", original[0], StringComparison.Ordinal);
        Assert.Equal(original, repository.GetAllElements().Select(element => element.ToString()).ToArray());
        await using var db = new NpgsqlConnection(connection);
        await db.OpenAsync();
        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT column_name, data_type, is_nullable FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = 'DataProtectionKeys' ORDER BY ordinal_position;
            """;
        await using (var reader = await command.ExecuteReaderAsync())
        {
            var rows = new List<string>();
            while (await reader.ReadAsync()) rows.Add($"{reader.GetString(0)}:{reader.GetString(1)}:{reader.GetString(2)}");
            Assert.Equal(["Id:integer:NO", "FriendlyName:text:YES", "Xml:text:YES"], rows);
        }
        command.CommandText = "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()";
        Assert.Equal(1L, await command.ExecuteScalarAsync());
    }

    [Fact]
    public async Task OriginalNullableAndEmptyXmlPlaceholders_AreRetainedWithoutReplacingProtectedKeys()
    {
        await using var ring = await EmployeeRememberedKeyRingFixture.CreateAsync(postgres);
        var connection = new NpgsqlConnectionStringBuilder(ring.Settings["ConnectionStrings:employee-data-protection"]!) { Pooling = false }.ConnectionString;
        var original = ring.ReadProtectedElements().Select(element => element.ToString()).ToArray();
        await using (var db = new NpgsqlConnection(connection))
        {
            await db.OpenAsync();
            await using var command = db.CreateCommand();
            command.CommandText = """
                INSERT INTO "DataProtectionKeys" ("FriendlyName", "Xml") VALUES ('nullable-original-placeholder', NULL), ('empty-original-placeholder', '');
                """;
            await command.ExecuteNonQueryAsync();
        }
        Assert.Equal(original, ring.ReadProtectedElements().Select(element => element.ToString()).ToArray());
        await using var readback = new NpgsqlConnection(connection);
        await readback.OpenAsync();
        await using var retained = readback.CreateCommand();
        retained.CommandText = "SELECT count(*) FROM \"DataProtectionKeys\" WHERE \"Xml\" IS NULL OR \"Xml\" = ''";
        Assert.Equal(2L, await retained.ExecuteScalarAsync());
    }

    [Fact]
    public async Task EmptyAdoptedRing_CannotSilentlyBecomeReplacementKeys()
    {
        await using var ring = await EmployeeRememberedKeyRingFixture.CreateAsync(postgres, seedKey: false);
        var repository = new EmployeeDataProtectionXmlRepository(ring.Settings["ConnectionStrings:employee-data-protection"]!);
        Assert.Throws<InvalidOperationException>(() => repository.GetAllElements());
    }

    [Theory]
    [InlineData("<key><descriptor><masterKey>synthetic-plaintext</masterKey></descriptor></key>", false)]
    [InlineData("<!DOCTYPE key [<!ENTITY forbidden SYSTEM 'file:///synthetic-do-not-read'>]><key>&forbidden;</key>", true)]
    public async Task AdoptedRecords_PlaintextAndDtdsFailClosed(string xml, bool dtd)
    {
        await using var ring = await EmployeeRememberedKeyRingFixture.CreateAsync(postgres, seedKey: false);
        var connection = new NpgsqlConnectionStringBuilder(ring.Settings["ConnectionStrings:employee-data-protection"]!) { Pooling = false }.ConnectionString;
        await using (var db = new NpgsqlConnection(connection))
        {
            await db.OpenAsync();
            await using var command = db.CreateCommand();
            command.CommandText = "INSERT INTO \"DataProtectionKeys\" (\"FriendlyName\", \"Xml\") VALUES ('synthetic-test-record', @xml)";
            command.Parameters.AddWithValue("xml", xml);
            await command.ExecuteNonQueryAsync();
        }
        var repository = new EmployeeDataProtectionXmlRepository(connection);
        if (dtd) Assert.Throws<XmlException>(() => repository.GetAllElements());
        else
        {
            var exception = Assert.Throws<InvalidOperationException>(() => repository.GetAllElements());
            Assert.DoesNotContain("synthetic-plaintext", exception.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task MissingSchema_IsFailureAndRuntimeNeverCreatesIt()
    {
        var connection = new NpgsqlConnectionStringBuilder(await postgres.CreateDatabaseAsync()) { Pooling = false }.ConnectionString;
        var repository = new EmployeeDataProtectionXmlRepository(connection);
        var exception = Assert.Throws<PostgresException>(() => repository.GetAllElements());
        Assert.Equal(PostgresErrorCodes.UndefinedTable, exception.SqlState);
        await using var db = new NpgsqlConnection(connection);
        await db.OpenAsync();
        await using var command = db.CreateCommand();
        command.CommandText = "SELECT count(*) FROM information_schema.tables WHERE table_name = 'DataProtectionKeys'";
        Assert.Equal(0L, await command.ExecuteScalarAsync());
    }
}
