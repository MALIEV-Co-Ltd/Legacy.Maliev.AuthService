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
        var existing = await dbContext.CreateOperations.AsNoTracking().SingleOrDefaultAsync(
            operation => operation.ServiceSubject == serviceSubject && operation.OperationKey == operationKey,
            cancellationToken);
        if (existing is not null)
        {
            return await ReconcileAsync(existing, databaseId, request, cancellationToken);
        }

        if (!AdministrativeIdentityPolicy.Accepts(request.UserName, request.Email))
            return new(CustomerIdentityCreateOutcome.InvalidIdentity, databaseId);

        var normalizedUserName = request.UserName.Trim().ToUpperInvariant();
        var normalizedEmail = request.Email.Trim().ToUpperInvariant();
        if (await dbContext.Users.AnyAsync(user => user.DatabaseID == databaseId ||
                user.NormalizedUserName == normalizedUserName || user.NormalizedEmail == normalizedEmail,
            cancellationToken))
        {
            existing = await dbContext.CreateOperations.AsNoTracking().SingleOrDefaultAsync(
                operation => operation.ServiceSubject == serviceSubject && operation.OperationKey == operationKey,
                cancellationToken);
            return existing is null
                ? new(CustomerIdentityCreateOutcome.Conflict, databaseId)
                : await ReconcileAsync(existing, databaseId, request, cancellationToken);
        }

        if (!AdministrativePasswordPolicy.Accepts(request.Password))
        {
            return new(CustomerIdentityCreateOutcome.InvalidPassword, databaseId);
        }

        var user = NewUser(databaseId, request);
        var salt = RandomNumberGenerator.GetBytes(16);
        dbContext.Users.Add(user);
        dbContext.CreateOperations.Add(new CustomerIdentityCreateOperation
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
            // A single SaveChanges transaction commits the identity and ownership proof together.
            await dbContext.SaveChangesAsync(cancellationToken);
            return new(CustomerIdentityCreateOutcome.Created, databaseId);
        }
        catch (DbUpdateException exception) when (exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            dbContext.ChangeTracker.Clear();
            existing = await dbContext.CreateOperations.AsNoTracking().SingleOrDefaultAsync(
                operation => operation.ServiceSubject == serviceSubject && operation.OperationKey == operationKey,
                cancellationToken);
            return existing is null
                ? new(CustomerIdentityCreateOutcome.Conflict, databaseId)
                : await ReconcileAsync(existing, databaseId, request, cancellationToken);
        }
    }

    private async Task<CustomerIdentityCreateResult> ReconcileAsync(
        CustomerIdentityCreateOperation operation, int databaseId,
        CreateCustomerIdentityRequest request, CancellationToken cancellationToken)
    {
        var hash = HashPayload(request, operation.PayloadSalt);
        if (operation.DatabaseId != databaseId ||
            !CryptographicOperations.FixedTimeEquals(hash, operation.PayloadHash))
        {
            return new(CustomerIdentityCreateOutcome.Conflict, databaseId);
        }

        // A receipt is ownership proof only while it still identifies the current user.
        var stillOwned = await dbContext.Users.AsNoTracking().AnyAsync(
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

        var normalizedUserName = request.UserName.Trim().ToUpperInvariant();
        var normalizedEmail = request.Email.Trim().ToUpperInvariant();
        var exists = await dbContext.Users.AnyAsync(
            user => user.DatabaseID == databaseId ||
                user.NormalizedUserName == normalizedUserName ||
                user.NormalizedEmail == normalizedEmail,
            cancellationToken);
        if (exists)
        {
            return null;
        }

        var user = NewUser(databaseId, request);
        dbContext.Users.Add(user);
        await dbContext.SaveChangesAsync(cancellationToken);
        return Project(user);
    }

    private LegacyIdentityRow NewUser(int databaseId, CreateCustomerIdentityRequest request)
    {
        var user = new LegacyIdentityRow
        {
            Id = Guid.NewGuid().ToString(),
            DatabaseID = databaseId,
            UserName = request.UserName.Trim(),
            NormalizedUserName = request.UserName.Trim().ToUpperInvariant(),
            Email = request.Email.Trim(),
            NormalizedEmail = request.Email.Trim().ToUpperInvariant(),
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
    public async Task<bool> UpdateAsync(
        int databaseId,
        UpdateCustomerIdentityRequest request,
        CancellationToken cancellationToken)
    {
        var user = await dbContext.Users.SingleOrDefaultAsync(
            value => value.DatabaseID == databaseId, cancellationToken);
        if (user is null)
        {
            return false;
        }

        if (!AdministrativeIdentityPolicy.Accepts(request.UserName, request.Email) ||
            await dbContext.Users.AnyAsync(value => value.Id != user.Id &&
                (value.NormalizedUserName == request.UserName.Trim().ToUpperInvariant() ||
                 value.NormalizedEmail == request.Email.Trim().ToUpperInvariant()), cancellationToken))
            throw new AdministrativeIdentityValidationException();

        user.UserName = request.UserName.Trim();
        user.NormalizedUserName = user.UserName.ToUpperInvariant();
        user.Email = request.Email.Trim();
        user.NormalizedEmail = user.Email.ToUpperInvariant();
        user.EmailConfirmed = request.EmailConfirmed;
        user.PhoneNumber = request.PhoneNumber;
        user.PhoneNumberConfirmed = request.PhoneNumberConfirmed;
        user.TwoFactorEnabled = request.TwoFactorEnabled;
        user.LockoutEnd = request.LockoutEnd;
        user.LockoutEnabled = request.LockoutEnabled;
        user.FaxNumber = request.FaxNumber;
        user.MobileNumber = request.MobileNumber;
        user.SecurityStamp = Guid.NewGuid().ToString();
        user.ConcurrencyStamp = Guid.NewGuid().ToString();
        await dbContext.SaveChangesAsync(cancellationToken);
        return true;
    }

    /// <inheritdoc />
    public async Task<bool> UpdateVersionedAsync(int databaseId, UpdateCustomerIdentityRequest request,
        string expectedVersion, CancellationToken cancellationToken)
    {
        var options = new DbContextOptionsBuilder<CustomerIdentityDbContext>(
            (DbContextOptions<CustomerIdentityDbContext>)dbContext.GetService<IDbContextOptions>())
            .UseNpgsql(dbContext.Database.GetConnectionString(), provider =>
                provider.ExecutionStrategy(dependencies => new NonRetryingExecutionStrategy(dependencies))).Options;
        await using var fresh = new CustomerIdentityDbContext(options);
        try
        {
            var user = await fresh.Users.AsNoTracking().SingleOrDefaultAsync(value => value.DatabaseID == databaseId, cancellationToken);
            if (user is null) return false;
            if (!IdentityAdminVersion.Matches(user, expectedVersion)) throw new AdministrativeIdentityConflictException();
            if (!AdministrativeIdentityPolicy.Accepts(request.UserName, request.Email) ||
                await fresh.Users.AnyAsync(value => value.Id != user.Id &&
                    (value.NormalizedUserName == request.UserName.Trim().ToUpperInvariant() ||
                     value.NormalizedEmail == request.Email.Trim().ToUpperInvariant()), cancellationToken))
                throw new AdministrativeIdentityValidationException();
            var name = request.UserName.Trim();
            var email = request.Email.Trim();
            var stamp = Guid.NewGuid().ToString();
            var concurrency = Guid.NewGuid().ToString();
            var written = await fresh.Users.Where(value => value.Id == user.Id && value.ConcurrencyStamp == user.ConcurrencyStamp)
                .ExecuteUpdateAsync(update => update
                    .SetProperty(value => value.UserName, name)
                    .SetProperty(value => value.NormalizedUserName, name.ToUpperInvariant())
                    .SetProperty(value => value.Email, email)
                    .SetProperty(value => value.NormalizedEmail, email.ToUpperInvariant())
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
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (AdministrativeIdentityConflictException) { throw; }
        catch (AdministrativeIdentityValidationException) { throw; }
        catch { throw new AdministrativeIdentityUnavailableException(); }
    }

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
