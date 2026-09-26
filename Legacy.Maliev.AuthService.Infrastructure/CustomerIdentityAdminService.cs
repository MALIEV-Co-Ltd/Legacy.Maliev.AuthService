using Legacy.Maliev.AuthService.Application;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
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
        user.MobileNumber);
}
