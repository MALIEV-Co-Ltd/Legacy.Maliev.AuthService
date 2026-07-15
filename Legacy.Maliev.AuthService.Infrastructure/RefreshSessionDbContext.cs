using Legacy.Maliev.AuthService.Domain;
using Microsoft.EntityFrameworkCore;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Isolated PostgreSQL store for revocable legacy sessions.</summary>
public sealed class RefreshSessionDbContext(DbContextOptions<RefreshSessionDbContext> options) : DbContext(options)
{
    /// <summary>Gets refresh sessions.</summary>
    public DbSet<RefreshSession> RefreshSessions => Set<RefreshSession>();

    /// <inheritdoc />
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        var session = modelBuilder.Entity<RefreshSession>();
        session.ToTable("refresh_sessions");
        session.HasKey(x => x.Id);
        session.Property(x => x.IdentityId).HasMaxLength(450).IsRequired();
        session.Property(x => x.TokenHash).HasMaxLength(64).IsRequired();
        session.HasIndex(x => x.TokenHash).IsUnique();
        session.HasIndex(x => x.FamilyId);
        session.HasIndex(x => x.ExpiresAt);
    }
}