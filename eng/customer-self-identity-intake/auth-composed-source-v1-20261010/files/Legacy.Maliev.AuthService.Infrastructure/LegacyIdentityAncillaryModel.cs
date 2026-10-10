using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Preserves original Identity persistence without registering an authorization or login provider.</summary>
internal static class LegacyIdentityAncillaryModel
{
    internal static void Configure(ModelBuilder model)
    {
        var role = model.Entity<IdentityRole>();
        role.ToTable("AspNetRoles");
        role.HasKey(value => value.Id);
        role.Property(value => value.Id).HasMaxLength(450);
        role.Property(value => value.Name).HasMaxLength(256);
        role.Property(value => value.NormalizedName).HasMaxLength(256);
        role.Property(value => value.ConcurrencyStamp).IsConcurrencyToken();
        role.HasIndex(value => value.NormalizedName).IsUnique().HasDatabaseName("RoleNameIndex");

        var roleClaim = model.Entity<IdentityRoleClaim<string>>();
        roleClaim.ToTable("AspNetRoleClaims");
        roleClaim.HasKey(value => value.Id);
        roleClaim.Property(value => value.Id).ValueGeneratedOnAdd();
        roleClaim.Property(value => value.RoleId).HasMaxLength(450).IsRequired();
        roleClaim.HasOne<IdentityRole>().WithMany().HasForeignKey(value => value.RoleId).OnDelete(DeleteBehavior.Cascade);

        var claim = model.Entity<IdentityUserClaim<string>>();
        claim.ToTable("AspNetUserClaims");
        claim.HasKey(value => value.Id);
        claim.Property(value => value.Id).ValueGeneratedOnAdd();
        claim.Property(value => value.UserId).HasMaxLength(450).IsRequired();
        claim.HasOne<LegacyIdentityRow>().WithMany().HasForeignKey(value => value.UserId).OnDelete(DeleteBehavior.Cascade);

        var login = model.Entity<IdentityUserLogin<string>>();
        login.ToTable("AspNetUserLogins");
        login.HasKey(value => new { value.LoginProvider, value.ProviderKey });
        login.Property(value => value.UserId).HasMaxLength(450).IsRequired();
        login.HasOne<LegacyIdentityRow>().WithMany().HasForeignKey(value => value.UserId).OnDelete(DeleteBehavior.Cascade);

        var membership = model.Entity<IdentityUserRole<string>>();
        membership.ToTable("AspNetUserRoles");
        membership.HasKey(value => new { value.UserId, value.RoleId });
        membership.Property(value => value.UserId).HasMaxLength(450);
        membership.Property(value => value.RoleId).HasMaxLength(450);
        membership.HasOne<LegacyIdentityRow>().WithMany().HasForeignKey(value => value.UserId).OnDelete(DeleteBehavior.Cascade);
        membership.HasOne<IdentityRole>().WithMany().HasForeignKey(value => value.RoleId).OnDelete(DeleteBehavior.Cascade);

        var token = model.Entity<IdentityUserToken<string>>();
        token.ToTable("AspNetUserTokens");
        token.HasKey(value => new { value.UserId, value.LoginProvider, value.Name });
        token.Property(value => value.UserId).HasMaxLength(450);
        token.HasOne<LegacyIdentityRow>().WithMany().HasForeignKey(value => value.UserId).OnDelete(DeleteBehavior.Cascade);
    }
}
