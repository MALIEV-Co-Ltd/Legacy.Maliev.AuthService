using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Creates only the isolated refresh-session context for migration tooling.</summary>
public sealed class RefreshSessionDesignTimeFactory : IDesignTimeDbContextFactory<RefreshSessionDbContext>
{
    /// <inheritdoc />
    public RefreshSessionDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<RefreshSessionDbContext>()
            .UseNpgsql("Host=localhost;Database=legacy_auth_design;Username=postgres")
            .Options;
        return new RefreshSessionDbContext(options);
    }
}