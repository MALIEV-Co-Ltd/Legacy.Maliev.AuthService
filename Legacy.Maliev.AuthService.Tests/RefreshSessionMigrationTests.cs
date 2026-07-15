using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class RefreshSessionMigrationTests
{
    [Fact]
    public void LatestScript_CreatesIdentityActionsOnlyInIsolatedPostgresStore()
    {
        var options = new DbContextOptionsBuilder<RefreshSessionDbContext>()
            .UseNpgsql("Host=localhost;Database=legacy_auth_script;Username=postgres")
            .Options;
        using var context = new RefreshSessionDbContext(options);

        var script = context.GetService<IMigrator>().GenerateScript(
            options: MigrationsSqlGenerationOptions.Idempotent);

        Assert.Contains("identity_action_tokens", script, StringComparison.Ordinal);
        Assert.Contains("CREATE TABLE", script, StringComparison.Ordinal);
        Assert.DoesNotContain("AspNetUsers", script, StringComparison.Ordinal);
        Assert.DoesNotContain("DROP TABLE", script, StringComparison.Ordinal);
        Assert.DoesNotContain("DROP COLUMN", script, StringComparison.Ordinal);
        Assert.DoesNotContain("ALTER COLUMN", script, StringComparison.Ordinal);
    }
}