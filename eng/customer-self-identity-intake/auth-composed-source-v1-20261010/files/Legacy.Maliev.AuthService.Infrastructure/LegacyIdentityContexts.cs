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

    /// <summary>Gets or sets whether this customer must replace its server-issued bootstrap credential.</summary>
    public bool PasswordSetupRequired { get; set; }

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
        LegacyIdentityAncillaryModel.Configure(modelBuilder);
        var user = modelBuilder.Entity<LegacyIdentityRow>();
        user.ToTable("AspNetUsers");
        user.HasKey(x => x.Id);
        user.Property(x => x.ConcurrencyStamp).IsConcurrencyToken();
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
            user.Ignore(x => x.PasswordSetupRequired);
        }
    }
}

/// <summary>Read-only customer identity context.</summary>
public sealed class CustomerIdentityDbContext(DbContextOptions<CustomerIdentityDbContext> options)
    : LegacyIdentityDbContext(options)
{
    /// <summary>Durable receipts for service-owned identity create operations.</summary>
    public DbSet<CustomerIdentityCreateOperation> CreateOperations => Set<CustomerIdentityCreateOperation>();

    /// <inheritdoc />
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        var operation = modelBuilder.Entity<CustomerIdentityCreateOperation>();
        operation.ToTable("CustomerIdentityCreateOperations");
        operation.HasKey(x => x.Id);
        operation.Property(x => x.ServiceSubject).HasMaxLength(256);
        operation.Property(x => x.PayloadHash).HasMaxLength(32);
        operation.Property(x => x.PayloadSalt).HasMaxLength(16);
        operation.Property(x => x.IdentityId).HasMaxLength(450);
        operation.HasIndex(x => new { x.ServiceSubject, x.OperationKey }).IsUnique();
        operation.HasIndex(x => x.DatabaseId).IsUnique();
    }
}

/// <summary>Ownership proof recorded atomically with one customer identity creation.</summary>
public sealed class CustomerIdentityCreateOperation
{
    /// <summary>Primary key.</summary>
    public long Id { get; set; }
    /// <summary>Authenticated service subject.</summary>
    public required string ServiceSubject { get; set; }
    /// <summary>Caller-supplied durable operation key.</summary>
    public Guid OperationKey { get; set; }
    /// <summary>Business identity identifier.</summary>
    public int DatabaseId { get; set; }
    /// <summary>Created identity key.</summary>
    public required string IdentityId { get; set; }
    /// <summary>Random salt for the canonical payload hash.</summary>
    public required byte[] PayloadSalt { get; set; }
    /// <summary>PBKDF2 hash of canonical payload, including the password.</summary>
    public required byte[] PayloadHash { get; set; }
}

/// <summary>Read-only employee identity context.</summary>
public sealed class EmployeeIdentityDbContext(DbContextOptions<EmployeeIdentityDbContext> options)
    : LegacyIdentityDbContext(options)
{
    public DbSet<EmployeeRecoveryEffect> RecoveryEffects => Set<EmployeeRecoveryEffect>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        var effect = modelBuilder.Entity<EmployeeRecoveryEffect>();
        effect.ToTable("EmployeeRecoveryEffects", table =>
        {
            table.HasCheckConstraint("CK_EmployeeRecoveryEffects_PurposePayload", "(\"Purpose\" = 'employee-password-reset' AND \"PasswordPayloadHash\" IS NOT NULL) OR (\"Purpose\" = 'employee-email-confirmation' AND \"PasswordPayloadHash\" IS NULL)");
            table.HasCheckConstraint("CK_EmployeeRecoveryEffects_Binding", "length(\"TokenSha256\") = 64 AND length(\"OwnerSubject\") > 0 AND length(\"BeforeSecurityStamp\") > 0 AND length(\"AfterSecurityStamp\") > 0");
        });
        effect.HasKey(x => x.ActionId);
        effect.Property(x => x.TokenSha256).HasMaxLength(64).IsRequired();
        effect.Property(x => x.Purpose).HasMaxLength(32).IsRequired();
        effect.Property(x => x.OwnerSubject).HasMaxLength(256).IsRequired();
        effect.Property(x => x.IdentityId).HasMaxLength(450).IsRequired();
        effect.Property(x => x.NormalizedEmail).HasMaxLength(256).IsRequired();
        effect.Property(x => x.BeforeSecurityStamp).IsRequired();
        effect.Property(x => x.AfterSecurityStamp).IsRequired();
        effect.Property(x => x.AfterConcurrencyStamp).IsRequired();
        effect.HasIndex(x => new { x.TokenSha256, x.Purpose }).IsUnique();
        effect.HasIndex(x => new { x.IdentityId, x.FinalizedAcknowledgedAt });
        effect.HasIndex(x => new { x.FinalizedAcknowledgedAt, x.AppliedAt });
    }
}
