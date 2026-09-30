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
    /// <summary>Gets one-time Google Identity Services nonces.</summary>
    public DbSet<GoogleIdentityNonce> GoogleIdentityNonces => Set<GoogleIdentityNonce>();

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
        action.ToTable("identity_action_tokens", table =>
        {
            table.HasCheckConstraint("CK_identity_action_tokens_employee_binding", "\"RecoveryVersion\" IS NULL OR (\"RecoveryVersion\" = 1 AND \"Purpose\" IN ('employee-password-reset', 'employee-email-confirmation') AND \"OriginalTokenSha256\" IS NOT NULL AND length(\"OriginalTokenSha256\") = 64 AND \"OwnerSubject\" IS NOT NULL AND length(\"OwnerSubject\") > 0 AND \"BoundNormalizedEmail\" IS NOT NULL AND length(\"BoundNormalizedEmail\") > 0 AND \"BoundSecurityStamp\" IS NOT NULL AND length(\"BoundSecurityStamp\") > 0)");
            table.HasCheckConstraint("CK_identity_action_tokens_employee_finalization", "(\"FinalizedAt\" IS NULL AND \"EffectActionId\" IS NULL) OR (\"RecoveryVersion\" IS NOT NULL AND \"RecoveryVersion\" = 1 AND \"FinalizedAt\" IS NOT NULL AND \"ConsumedAt\" IS NOT NULL AND \"EffectActionId\" IS NOT NULL AND \"EffectActionId\" = \"Id\")");
        });
        action.HasKey(x => x.Id);
        action.Property(x => x.IdentityId).HasMaxLength(450).IsRequired();
        action.Property(x => x.TokenHash).HasMaxLength(64).IsRequired();
        action.Property(x => x.Purpose).HasMaxLength(32).IsRequired();
        action.Property(x => x.TargetEmail).HasMaxLength(320);
        action.Property(x => x.OriginalTokenSha256).HasMaxLength(64);
        action.Property(x => x.OwnerSubject).HasMaxLength(256);
        action.Property(x => x.BoundNormalizedEmail).HasMaxLength(256);
        action.HasIndex(x => new { x.OriginalTokenSha256, x.Purpose }).IsUnique();
        action.HasIndex(x => new { x.IdentityId, x.Purpose, x.TokenHash }).IsUnique();
        action.HasIndex(x => x.ExpiresAt);

        var googleNonce = modelBuilder.Entity<GoogleIdentityNonce>();
        googleNonce.ToTable("google_identity_nonces");
        googleNonce.HasKey(x => x.Id);
        googleNonce.Property(x => x.NonceHash).HasMaxLength(64).IsRequired();
        googleNonce.Property(x => x.ServiceName).HasMaxLength(128).IsRequired();
        googleNonce.Property(x => x.Application).HasMaxLength(64).IsRequired();
        googleNonce.HasIndex(x => x.NonceHash).IsUnique();
        googleNonce.HasIndex(x => x.ExpiresAt);
    }
}
