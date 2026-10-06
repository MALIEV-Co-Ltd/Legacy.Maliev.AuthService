using Legacy.Maliev.AuthService.Application;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage;
using Npgsql;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Administers customer identities without changing the legacy ASP.NET Identity schema.</summary>
public sealed class CustomerIdentityAdminService(
    CustomerIdentityDbContext dbContext,
    IPasswordHasher<LegacyIdentityRow> passwordHasher) : ICustomerIdentityAdminService
{
    /// <inheritdoc />
    public async Task<CustomerIdentityCreateResult> CreateOrReconcileAsync(
        int databaseId, string serviceSubject, Guid operationKey,
        CreateCustomerIdentityRequest request, CancellationToken cancellationToken)
    {
        await using var fresh = NewNonRetryingContext();
        var existing = await fresh.CreateOperations.AsNoTracking().SingleOrDefaultAsync(
            operation => operation.ServiceSubject == serviceSubject && operation.OperationKey == operationKey,
            cancellationToken);
        if (existing is not null) return await ReconcileAsync(fresh, existing, databaseId, request, cancellationToken);
        if (!AdministrativeIdentityPolicy.Accepts(request.UserName, request.Email))
            return new(CustomerIdentityCreateOutcome.InvalidIdentity, databaseId);

        await using var transaction = await fresh.Database.BeginTransactionAsync(cancellationToken);
        await fresh.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT pg_advisory_xact_lock(hashtextextended({"customer-create-operation:" + serviceSubject + ":" + operationKey.ToString("D")}, 2))", cancellationToken);
        existing = await fresh.CreateOperations.AsNoTracking().SingleOrDefaultAsync(
            operation => operation.ServiceSubject == serviceSubject && operation.OperationKey == operationKey,
            cancellationToken);
        if (existing is not null) return await ReconcileAsync(fresh, existing, databaseId, request, cancellationToken);
        await LockProfileAsync(fresh, databaseId, cancellationToken);
        await LegacyIdentityKeyOwnership.LockAsync(fresh, request.Email, cancellationToken);
        await LegacyIdentityKeyOwnership.LockUserNameAsync(fresh, request.UserName, cancellationToken);
        var normalizedUserName = request.UserName.Trim().Normalize().ToUpperInvariant();
        if (await fresh.Users.AnyAsync(user => user.DatabaseID == databaseId ||
                user.NormalizedUserName == normalizedUserName, cancellationToken) ||
            await LegacyIdentityKeyOwnership.HasOtherUserNameOwnerAsync(fresh, request.UserName, null, cancellationToken) ||
            await LegacyIdentityKeyOwnership.HasOtherOwnerAsync(fresh, request.Email, null, cancellationToken))
            return new(CustomerIdentityCreateOutcome.Conflict, databaseId);
        if (!AdministrativePasswordPolicy.Accepts(request.Password))
            return new(CustomerIdentityCreateOutcome.InvalidPassword, databaseId);

        var user = NewUser(databaseId, request);
        var salt = RandomNumberGenerator.GetBytes(16);
        fresh.Users.Add(user);
        fresh.CreateOperations.Add(new CustomerIdentityCreateOperation
        {
            ServiceSubject = serviceSubject,
            OperationKey = operationKey,
            DatabaseId = databaseId,
            IdentityId = user.Id,
            PayloadSalt = salt,
            PayloadHash = HashPayload(request, salt),
        });
        try
        {
            // The canonical ownership lock, identity and unchanged raw-request receipt commit together.
            await fresh.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return new(CustomerIdentityCreateOutcome.Created, databaseId);
        }
        catch (DbUpdateException exception) when (exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            await transaction.RollbackAsync(cancellationToken);
            await transaction.DisposeAsync();
            fresh.ChangeTracker.Clear();
            existing = await fresh.CreateOperations.AsNoTracking().SingleOrDefaultAsync(
                operation => operation.ServiceSubject == serviceSubject && operation.OperationKey == operationKey,
                cancellationToken);
            return existing is null ? new(CustomerIdentityCreateOutcome.Conflict, databaseId)
                : await ReconcileAsync(fresh, existing, databaseId, request, cancellationToken);
        }
    }

    private static async Task<CustomerIdentityCreateResult> ReconcileAsync(
        CustomerIdentityDbContext context, CustomerIdentityCreateOperation operation, int databaseId,
        CreateCustomerIdentityRequest request, CancellationToken cancellationToken)
    {
        var hash = HashPayload(request, operation.PayloadSalt);
        if (operation.DatabaseId != databaseId ||
            !CryptographicOperations.FixedTimeEquals(hash, operation.PayloadHash))
        {
            return new(CustomerIdentityCreateOutcome.Conflict, databaseId);
        }

        // A receipt is ownership proof only while it still identifies the current user.
        var stillOwned = await context.Users.AsNoTracking().AnyAsync(
            user => user.Id == operation.IdentityId && user.DatabaseID == databaseId,
            cancellationToken);
        return new(stillOwned ? CustomerIdentityCreateOutcome.Replayed : CustomerIdentityCreateOutcome.Conflict,
            databaseId);
    }

    private static byte[] HashPayload(CreateCustomerIdentityRequest request, byte[] salt)
    {
        var canonical = JsonSerializer.Serialize(request);
        return Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(canonical), salt, 210_000, HashAlgorithmName.SHA256, 32);
    }

    /// <inheritdoc />
    public async Task<CustomerIdentityResponse?> CreateAsync(
        int databaseId,
        CreateCustomerIdentityRequest request,
        CancellationToken cancellationToken)
    {
        if (!AdministrativePasswordPolicy.Accepts(request.Password)) return null;
        if (!AdministrativeIdentityPolicy.Accepts(request.UserName, request.Email))
            throw new AdministrativeIdentityValidationException();

        await using var fresh = NewNonRetryingContext();
        await using var transaction = await fresh.Database.BeginTransactionAsync(cancellationToken);
        await LockProfileAsync(fresh, databaseId, cancellationToken);
        await LegacyIdentityKeyOwnership.LockAsync(fresh, request.Email, cancellationToken);
        await LegacyIdentityKeyOwnership.LockUserNameAsync(fresh, request.UserName, cancellationToken);
        var normalizedUserName = request.UserName.Trim().Normalize().ToUpperInvariant();
        if (await fresh.Users.AnyAsync(user => user.DatabaseID == databaseId ||
                user.NormalizedUserName == normalizedUserName, cancellationToken) ||
            await LegacyIdentityKeyOwnership.HasOtherUserNameOwnerAsync(fresh, request.UserName, null, cancellationToken) ||
            await LegacyIdentityKeyOwnership.HasOtherOwnerAsync(fresh, request.Email, null, cancellationToken)) return null;
        var user = NewUser(databaseId, request);
        fresh.Users.Add(user);
        await fresh.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return Project(user);
    }

    private LegacyIdentityRow NewUser(int databaseId, CreateCustomerIdentityRequest request)
    {
        var user = new LegacyIdentityRow
        {
            Id = Guid.NewGuid().ToString(),
            DatabaseID = databaseId,
            UserName = request.UserName.Trim(),
            NormalizedUserName = request.UserName.Trim().Normalize().ToUpperInvariant(),
            Email = request.Email.Trim(),
            NormalizedEmail = LegacyIdentityKeyOwnership.CanonicalKey(request.Email),
            EmailConfirmed = request.EmailConfirmed,
            PhoneNumber = request.PhoneNumber,
            PhoneNumberConfirmed = false,
            TwoFactorEnabled = false,
            LockoutEnabled = true,
            AccessFailedCount = 0,
            FaxNumber = request.FaxNumber,
            MobileNumber = request.MobileNumber,
            PasswordSetupRequired = request.PasswordSetupRequired,
            SecurityStamp = Guid.NewGuid().ToString(),
            ConcurrencyStamp = Guid.NewGuid().ToString(),
        };
        user.PasswordHash = passwordHasher.HashPassword(user, request.Password);
        return user;
    }

    /// <inheritdoc />
    public async Task<CustomerIdentityResponse?> GetAsync(int databaseId, CancellationToken cancellationToken)
    {
        var user = await dbContext.Users.AsNoTracking()
            .SingleOrDefaultAsync(value => value.DatabaseID == databaseId, cancellationToken);
        return user is null ? null : Project(user);
    }

    /// <inheritdoc />
    public Task<bool> UpdateAsync(int databaseId, UpdateCustomerIdentityRequest request,
        CancellationToken cancellationToken) => UpdateCoreAsync(databaseId, request, null, cancellationToken);

    /// <inheritdoc />
    public Task<bool> UpdateVersionedAsync(int databaseId, UpdateCustomerIdentityRequest request,
        string expectedVersion, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(expectedVersion)) throw new AdministrativeIdentityConflictException();
        return UpdateCoreAsync(databaseId, request, expectedVersion, cancellationToken);
    }

    private async Task<bool> UpdateCoreAsync(int databaseId, UpdateCustomerIdentityRequest request,
        string? expectedVersion, CancellationToken cancellationToken)
    {
        await using var fresh = NewNonRetryingContext();
        try
        {
            await using var transaction = await fresh.Database.BeginTransactionAsync(cancellationToken);
            var user = await fresh.Users.FromSqlInterpolated(
                $"SELECT * FROM \"AspNetUsers\" WHERE \"DatabaseID\" = {databaseId} FOR UPDATE")
                .AsNoTracking().SingleOrDefaultAsync(cancellationToken);
            if (user is null) return false;
            if (expectedVersion is not null && !IdentityAdminVersion.Matches(user, expectedVersion))
                throw new AdministrativeIdentityConflictException();
            if (!AdministrativeIdentityPolicy.Accepts(request.UserName, request.Email))
                throw new AdministrativeIdentityValidationException();
            await LegacyIdentityKeyOwnership.LockAsync(fresh, request.Email, cancellationToken);
            await LegacyIdentityKeyOwnership.LockUserNameAsync(fresh, request.UserName, cancellationToken);
            var name = request.UserName.Trim();
            var normalizedName = name.Normalize().ToUpperInvariant();
            if (await fresh.Users.AnyAsync(value => value.Id != user.Id &&
                    value.NormalizedUserName == normalizedName, cancellationToken) ||
                await LegacyIdentityKeyOwnership.HasOtherUserNameOwnerAsync(fresh, request.UserName, user.Id, cancellationToken) ||
                await LegacyIdentityKeyOwnership.HasOtherOwnerAsync(fresh, request.Email, user.Id, cancellationToken))
                throw new AdministrativeIdentityValidationException();
            var email = request.Email.Trim();
            var normalizedEmail = LegacyIdentityKeyOwnership.CanonicalKey(email);
            var stamp = Guid.NewGuid().ToString();
            var concurrency = Guid.NewGuid().ToString();
            var written = await fresh.Users.Where(value => value.Id == user.Id && value.ConcurrencyStamp == user.ConcurrencyStamp)
                .ExecuteUpdateAsync(update => update
                    .SetProperty(value => value.UserName, name)
                    .SetProperty(value => value.NormalizedUserName, normalizedName)
                    .SetProperty(value => value.Email, email)
                    .SetProperty(value => value.NormalizedEmail, normalizedEmail)
                    .SetProperty(value => value.EmailConfirmed, request.EmailConfirmed)
                    .SetProperty(value => value.PhoneNumber, request.PhoneNumber)
                    .SetProperty(value => value.PhoneNumberConfirmed, request.PhoneNumberConfirmed)
                    .SetProperty(value => value.TwoFactorEnabled, request.TwoFactorEnabled)
                    .SetProperty(value => value.LockoutEnd, request.LockoutEnd)
                    .SetProperty(value => value.LockoutEnabled, request.LockoutEnabled)
                    .SetProperty(value => value.FaxNumber, request.FaxNumber)
                    .SetProperty(value => value.MobileNumber, request.MobileNumber)
                    .SetProperty(value => value.SecurityStamp, stamp)
                    .SetProperty(value => value.ConcurrencyStamp, concurrency), cancellationToken);
            if (written != 1) throw new AdministrativeIdentityConflictException();
            await transaction.CommitAsync(cancellationToken);
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (AdministrativeIdentityConflictException) { throw; }
        catch (AdministrativeIdentityValidationException) { throw; }
        catch { throw new AdministrativeIdentityUnavailableException(); }
    }

    private CustomerIdentityDbContext NewNonRetryingContext() => new(
        new DbContextOptionsBuilder<CustomerIdentityDbContext>(
            (DbContextOptions<CustomerIdentityDbContext>)dbContext.GetService<IDbContextOptions>())
            .UseNpgsql(dbContext.Database.GetConnectionString(), provider =>
                provider.ExecutionStrategy(dependencies => new NonRetryingExecutionStrategy(dependencies))).Options);

    internal static Task<int> LockProfileAsync(CustomerIdentityDbContext context, int databaseId,
        CancellationToken cancellationToken) => context.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT pg_advisory_xact_lock(hashtextextended({"customer-create:" + databaseId}, 1))", cancellationToken);

    /// <inheritdoc />
    public async Task<bool> DeleteAsync(int databaseId, CancellationToken cancellationToken)
    {
        var user = await dbContext.Users.SingleOrDefaultAsync(
            value => value.DatabaseID == databaseId, cancellationToken);
        if (user is null)
        {
            return false;
        }

        dbContext.Users.Remove(user);
        await dbContext.SaveChangesAsync(cancellationToken);
        return true;
    }

    private static CustomerIdentityResponse Project(LegacyIdentityRow user) => new(
        user.Id,
        user.UserName,
        user.Email,
        user.EmailConfirmed,
        user.PhoneNumber,
        user.PhoneNumberConfirmed,
        user.TwoFactorEnabled,
        user.LockoutEnd,
        user.LockoutEnabled,
        user.AccessFailedCount,
        user.DatabaseID ?? 0,
        user.FaxNumber,
        user.MobileNumber,
        IdentityAdminVersion.Get(user));
}
