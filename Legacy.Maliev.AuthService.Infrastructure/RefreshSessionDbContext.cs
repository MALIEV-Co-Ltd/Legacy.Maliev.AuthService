using Legacy.Maliev.AuthService.Domain;
using Microsoft.EntityFrameworkCore;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Isolated PostgreSQL store for revocable legacy sessions.</summary>
public sealed class RefreshSessionDbContext(DbContextOptions<RefreshSessionDbContext> options) : DbContext(options)
{
    /// <summary>Gets refresh sessions.</summary>
    public DbSet<RefreshSession> RefreshSessions => Set<RefreshSession>();
    /// <summary>Gets hashed single-use identity actions.</summary>
    public DbSet<IdentityActionToken> IdentityActionTokens => Set<IdentityActionToken>();

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

        var action = modelBuilder.Entity<IdentityActionToken>();
        action.ToTable("identity_action_tokens");
        action.HasKey(x => x.Id);
        action.Property(x => x.IdentityId).HasMaxLength(450).IsRequired();
        action.Property(x => x.TokenHash).HasMaxLength(64).IsRequired();
        action.Property(x => x.Purpose).HasMaxLength(32).IsRequired();
        action.HasIndex(x => new { x.IdentityId, x.Purpose, x.TokenHash }).IsUnique();
        action.HasIndex(x => x.ExpiresAt);
    }
}