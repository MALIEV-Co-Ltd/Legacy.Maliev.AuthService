using Microsoft.EntityFrameworkCore;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Read projection for the unchanged AspNetUsers table.</summary>
public sealed class LegacyIdentityRow
{
    /// <summary>Gets or sets the identity key.</summary>
    public required string Id { get; set; }

    /// <summary>Gets or sets the user name.</summary>
    public string? UserName { get; set; }

    /// <summary>Gets or sets the normalized user name.</summary>
    public string? NormalizedUserName { get; set; }

    /// <summary>Gets or sets the email address.</summary>
    public string? Email { get; set; }

    /// <summary>Gets or sets the normalized email.</summary>
    public string? NormalizedEmail { get; set; }

    /// <summary>Gets or sets whether the email is confirmed.</summary>
    public bool EmailConfirmed { get; set; }

    /// <summary>Gets or sets the password hash.</summary>
    public string? PasswordHash { get; set; }

    /// <summary>Gets or sets the security stamp.</summary>
    public string? SecurityStamp { get; set; }

    /// <summary>Gets or sets the concurrency stamp.</summary>
    public string? ConcurrencyStamp { get; set; }

    /// <summary>Gets or sets the telephone number.</summary>
    public string? PhoneNumber { get; set; }

    /// <summary>Gets or sets whether the telephone number is confirmed.</summary>
    public bool PhoneNumberConfirmed { get; set; }

    /// <summary>Gets or sets whether two-factor authentication is enabled.</summary>
    public bool TwoFactorEnabled { get; set; }

    /// <summary>Gets or sets the business database identifier.</summary>
    public int? DatabaseID { get; set; }

    /// <summary>Gets or sets the legacy fax number.</summary>
    public string? FaxNumber { get; set; }

    /// <summary>Gets or sets the legacy mobile number.</summary>
    public string? MobileNumber { get; set; }

    /// <summary>Gets or sets whether lockout is enabled.</summary>
    public bool LockoutEnabled { get; set; }

    /// <summary>Gets or sets the current lockout end.</summary>
    public DateTimeOffset? LockoutEnd { get; set; }

    /// <summary>Gets or sets the failed access counter.</summary>
    public int AccessFailedCount { get; set; }
}

/// <summary>Base read-only mapping shared by the two unchanged identity databases.</summary>
public abstract class LegacyIdentityDbContext(DbContextOptions options) : DbContext(options)
{
    /// <summary>Gets the legacy users.</summary>
    public DbSet<LegacyIdentityRow> Users => Set<LegacyIdentityRow>();

    /// <inheritdoc />
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        var user = modelBuilder.Entity<LegacyIdentityRow>();
        user.ToTable("AspNetUsers");
        user.HasKey(x => x.Id);
        user.Property(x => x.Id).HasMaxLength(450);
        user.Property(x => x.UserName).HasMaxLength(256);
        user.Property(x => x.NormalizedUserName).HasMaxLength(256);
        user.Property(x => x.Email).HasMaxLength(256);
        user.Property(x => x.NormalizedEmail).HasMaxLength(256);
        user.HasIndex(x => x.NormalizedUserName)
            .IsUnique()
            .HasDatabaseName("UserNameIndex");
        user.HasIndex(x => x.NormalizedEmail)
            .HasDatabaseName("EmailIndex");
        if (this is EmployeeIdentityDbContext)
        {
            user.Ignore(x => x.FaxNumber);
            user.Ignore(x => x.MobileNumber);
        }
    }
}

/// <summary>Read-only customer identity context.</summary>
public sealed class CustomerIdentityDbContext(DbContextOptions<CustomerIdentityDbContext> options)
    : LegacyIdentityDbContext(options);

/// <summary>Read-only employee identity context.</summary>
public sealed class EmployeeIdentityDbContext(DbContextOptions<EmployeeIdentityDbContext> options)
    : LegacyIdentityDbContext(options);
