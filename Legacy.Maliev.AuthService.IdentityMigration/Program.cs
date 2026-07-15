using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.EntityFrameworkCore;

var options = MigrationOptions.Parse(args);
IdentityDataMigrator.EnsureReadOnlySqlServerSource(options.SourceConnectionString);

var report = options.Kind switch
{
    IdentityKind.Customer => await RunCustomerAsync(options),
    IdentityKind.Employee => await RunEmployeeAsync(options),
    _ => throw new InvalidOperationException("Unsupported identity database kind.")
};

Console.WriteLine(
    "Identity migration validation succeeded. " +
    $"kind={options.Kind.ToString().ToLowerInvariant()} rows={report.SourceCount} fingerprint={report.Fingerprint}");

static async Task<IdentityMigrationReport> RunCustomerAsync(MigrationOptions options)
{
    await using var source = new CustomerIdentityDbContext(
        new DbContextOptionsBuilder<CustomerIdentityDbContext>()
            .UseSqlServer(options.SourceConnectionString)
            .Options);
    await using var destination = new CustomerIdentityDbContext(
        new DbContextOptionsBuilder<CustomerIdentityDbContext>()
            .UseNpgsql(options.TargetConnectionString)
            .Options);
    await destination.Database.MigrateAsync();
    var rows = source.Users.AsNoTracking().OrderBy(row => row.Id).AsAsyncEnumerable();
    return options.Mode == MigrationMode.Copy
        ? await IdentityDataMigrator.CopyAndValidateAsync(rows, destination, includeCustomerFields: true)
        : await IdentityDataMigrator.ValidateAsync(rows, destination, includeCustomerFields: true);
}

static async Task<IdentityMigrationReport> RunEmployeeAsync(MigrationOptions options)
{
    await using var source = new EmployeeIdentityDbContext(
        new DbContextOptionsBuilder<EmployeeIdentityDbContext>()
            .UseSqlServer(options.SourceConnectionString)
            .Options);
    await using var destination = new EmployeeIdentityDbContext(
        new DbContextOptionsBuilder<EmployeeIdentityDbContext>()
            .UseNpgsql(options.TargetConnectionString)
            .Options);
    await destination.Database.MigrateAsync();
    var rows = source.Users.AsNoTracking().OrderBy(row => row.Id).AsAsyncEnumerable();
    return options.Mode == MigrationMode.Copy
        ? await IdentityDataMigrator.CopyAndValidateAsync(rows, destination, includeCustomerFields: false)
        : await IdentityDataMigrator.ValidateAsync(rows, destination, includeCustomerFields: false);
}

internal sealed record MigrationOptions(
    IdentityKind Kind,
    MigrationMode Mode,
    string SourceConnectionString,
    string TargetConnectionString)
{
    public static MigrationOptions Parse(string[] args)
    {
        var values = args
            .Chunk(2)
            .Where(pair => pair.Length == 2 && pair[0].StartsWith("--", StringComparison.Ordinal))
            .ToDictionary(pair => pair[0][2..], pair => pair[1], StringComparer.OrdinalIgnoreCase);

        var kindValue = Read(values, "kind", "IDENTITY_MIGRATION_KIND");
        var modeValue = Read(values, "mode", "IDENTITY_MIGRATION_MODE");
        var source = Read(values, "source", "IDENTITY_SOURCE_CONNECTION_STRING");
        var target = Read(values, "target", "IDENTITY_TARGET_CONNECTION_STRING");
        if (!Enum.TryParse<IdentityKind>(kindValue, ignoreCase: true, out var kind) ||
            !Enum.TryParse<MigrationMode>(modeValue, ignoreCase: true, out var mode))
        {
            throw new InvalidOperationException("Use --kind customer|employee and --mode copy|validate.");
        }

        return new(kind, mode, source, target);
    }

    private static string Read(IReadOnlyDictionary<string, string> values, string key, string environmentName)
    {
        var value = values.GetValueOrDefault(key) ?? Environment.GetEnvironmentVariable(environmentName);
        return string.IsNullOrWhiteSpace(value)
            ? throw new InvalidOperationException($"Missing --{key} or {environmentName}.")
            : value;
    }
}

internal enum IdentityKind
{
    Customer,
    Employee
}

internal enum MigrationMode
{
    Copy,
    Validate
}
