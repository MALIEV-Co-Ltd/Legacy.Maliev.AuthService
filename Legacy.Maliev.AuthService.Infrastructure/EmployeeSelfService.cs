using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Coordinates employee recovery using an atomic identity receipt and retryable Auth finalization.</summary>
public sealed class EmployeeSelfService(EmployeeIdentityDbContext employees, RefreshSessionDbContext state,
    IPasswordHasher<LegacyIdentityRow> passwordHasher, TimeProvider timeProvider, EmployeeRecoveryOptions? options = null)
{
    internal const string EmailConfirmation = "employee-email-confirmation";
    internal const string PasswordReset = "employee-password-reset";
    private EmployeeIdentityDbContext NewEmployees() => new((DbContextOptions<EmployeeIdentityDbContext>)employees.GetService<IDbContextOptions>());
    private RefreshSessionDbContext NewState() => new((DbContextOptions<RefreshSessionDbContext>)state.GetService<IDbContextOptions>());

    public Task<EmployeeActionChallenge> RequestEmailConfirmationAsync(EmployeeActionRequest request, string ownerSubject, CancellationToken cancellationToken) =>
        CreateChallengeAsync(request.Email, ownerSubject, EmailConfirmation, true, cancellationToken);
    public Task<EmployeeActionChallenge> RequestPasswordResetAsync(EmployeeActionRequest request, string ownerSubject, CancellationToken cancellationToken) =>
        CreateChallengeAsync(request.Email, ownerSubject, PasswordReset, false, cancellationToken);
    public Task<bool> ConfirmEmailAsync(CompleteEmployeeActionRequest request, string ownerSubject, CancellationToken cancellationToken) =>
        CompleteAsync(request.Email, request.Token, null, ownerSubject, EmailConfirmation, cancellationToken);
    public Task<bool> CompletePasswordResetAsync(CompleteEmployeePasswordResetRequest request, string ownerSubject, CancellationToken cancellationToken) =>
        CompleteAsync(request.Email, request.Token, request.Password, ownerSubject, PasswordReset, cancellationToken);

    private async Task EnsureReadyAsync(CancellationToken cancellationToken)
    {
        if (options?.Enabled != true) throw new EmployeeRecoveryUnavailableException();
        await using var employeeProbe = NewEmployees();
        await using var stateProbe = NewState();
        await EmployeeRecoverySchema.EnsureAsync(employeeProbe, stateProbe, cancellationToken);
    }

    private async Task<EmployeeActionChallenge> CreateChallengeAsync(string email, string owner, string purpose, bool requireUnconfirmed, CancellationToken cancellationToken)
    {
        if (!ValidOwner(owner)) throw new EmployeeRecoveryUnavailableException();
        await EnsureReadyAsync(cancellationToken);
        var normalized = Normalize(email);
        // Bootstrap is a conditional write before the coordinator, never an overwrite of a winning admin/bootstrap.
        await using var lookup = NewEmployees();
        var observed = await lookup.Users.AsNoTracking().SingleOrDefaultAsync(x => x.NormalizedEmail == normalized, cancellationToken);
        if (observed is null || (requireUnconfirmed && observed.EmailConfirmed)) return new(true, null);
        if (string.IsNullOrWhiteSpace(observed.SecurityStamp))
        {
            var initial = Guid.NewGuid().ToString();
            var changed = await lookup.Users.Where(x => x.Id == observed.Id && x.SecurityStamp == observed.SecurityStamp && x.NormalizedEmail == normalized)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.SecurityStamp, initial), cancellationToken);
            if (changed != 1) return new(true, null);
        }
        var acknowledgements = new List<Guid>();
        var result = await state.Database.CreateExecutionStrategy().ExecuteAsync(async () =>
        {
            acknowledgements.Clear();
            await using var auth = NewState();
            await using var transaction = await auth.Database.BeginTransactionAsync(cancellationToken);
            await LockCoordinatorAsync(auth, observed.Id, cancellationToken);
            // Reconcile committed effects before superseding; never acquire Auth locks while holding an identity lock.
            await using (var reader = NewEmployees())
            {
                var pending = await reader.RecoveryEffects.AsNoTracking().Where(x => x.IdentityId == observed.Id && x.FinalizedAcknowledgedAt == null)
                    .OrderBy(x => x.AppliedAt).ToListAsync(cancellationToken);
                foreach (var receipt in pending)
                {
                    await FinalizeAsync(auth, receipt, cancellationToken);
                    acknowledgements.Add(receipt.ActionId);
                }
            }
            await using var strategyContext = NewEmployees();
            var locked = await strategyContext.Database.CreateExecutionStrategy().ExecuteAsync(async () =>
            {
                await using var fresh = NewEmployees();
                await using var identityTransaction = await fresh.Database.BeginTransactionAsync(cancellationToken);
                var row = await LockIdentityAsync(fresh, observed.Id, cancellationToken);
                if (row is null || row.NormalizedEmail != normalized || string.IsNullOrWhiteSpace(row.SecurityStamp) || (requireUnconfirmed && row.EmailConfirmed)) return null;
                await identityTransaction.CommitAsync(cancellationToken);
                return row;
            });
            if (locked is null)
            {
                await transaction.CommitAsync(cancellationToken);
                return new EmployeeActionChallenge(true, null);
            }
            var token = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
            var now = timeProvider.GetUtcNow();
            await auth.IdentityActionTokens.Where(x => x.IdentityId == locked.Id && x.Purpose == purpose && x.ConsumedAt == null)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.ConsumedAt, now), cancellationToken);
            auth.IdentityActionTokens.Add(new()
            {
                Id = Guid.NewGuid(),
                IdentityId = locked.Id,
                Purpose = purpose,
                TokenHash = HashBoundToken(token, locked.SecurityStamp!, normalized),
                OriginalTokenSha256 = HashToken(token),
                OwnerSubject = owner,
                BoundNormalizedEmail = normalized,
                BoundSecurityStamp = locked.SecurityStamp,
                RecoveryVersion = 1,
                CreatedAt = now,
                ExpiresAt = now.AddHours(24),
            });
            await auth.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return new EmployeeActionChallenge(true, token);
        });
        foreach (var id in acknowledgements) await AcknowledgeAsync(id, cancellationToken);
        return result;
    }

    private async Task<bool> CompleteAsync(string email, string token, string? password, string owner, string purpose, CancellationToken cancellationToken)
    {
        if (!ValidOwner(owner)) return false;
        await EnsureReadyAsync(cancellationToken);
        var normalized = Normalize(email);
        var digest = HashToken(token);
        var attemptedFinalizations = new HashSet<Guid>();
        Guid? acknowledgement = null;
        try
        {
            // Auth retries use fresh contexts. The separate employee transaction always probes its durable receipt
            // UNDER the identity lock before mutation, including unknown prior commit outcomes. Never blindly replay two DBs.
            var result = await state.Database.CreateExecutionStrategy().ExecuteAsync(async () =>
            {
                await using var auth = NewState();
                var candidate = await auth.IdentityActionTokens.AsNoTracking().SingleOrDefaultAsync(x => x.OriginalTokenSha256 == digest && x.Purpose == purpose && x.RecoveryVersion == 1, cancellationToken);
                if (candidate is null || candidate.OwnerSubject != owner || candidate.BoundNormalizedEmail != normalized) return false;
                await using var transaction = await auth.Database.BeginTransactionAsync(cancellationToken);
                await LockCoordinatorAsync(auth, candidate.IdentityId, cancellationToken);
                var action = await LockActionAsync(auth, candidate.Id, cancellationToken);
                if (action is null || action.OwnerSubject != owner || action.BoundNormalizedEmail != normalized) return false;
                await using var probe = NewEmployees();
                var receipt = await probe.RecoveryEffects.AsNoTracking().SingleOrDefaultAsync(x => x.ActionId == action.Id, cancellationToken);
                if (action.ConsumedAt is not null)
                {
                    // Confirm an unknown Auth commit from THIS call, not a later terminal replay.
                    if (action.FinalizedAt is null || !attemptedFinalizations.Contains(action.Id) || receipt is null || !Matches(receipt, action, password)) return false;
                    acknowledgement = action.Id;
                    return true;
                }
                if (receipt is not null)
                {
                    if (!Matches(receipt, action, password)) return false;
                }
                else
                {
                    if (action.ExpiresAt <= timeProvider.GetUtcNow()) return false;
                    // Nonterminal reservation precedes identity locking; a winning admin is re-read under FOR UPDATE.
                    await auth.IdentityActionTokens.Where(x => x.Id == action.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.RecoveryVersion, 1), cancellationToken);
                    receipt = await ApplyIdentityEffectAsync(action, password, cancellationToken);
                    if (receipt is null || !Matches(receipt, action, password)) return false;
                }
                attemptedFinalizations.Add(action.Id);
                await FinalizeAsync(auth, receipt, cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                acknowledgement = action.Id;
                return true;
            });
            if (acknowledgement is { } id) await AcknowledgeAsync(id, cancellationToken);
            return result;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (EmployeeRecoveryUnavailableException) { throw; }
        catch { throw new EmployeeRecoveryUnavailableException(); }
    }

    private async Task<EmployeeRecoveryEffect?> ApplyIdentityEffectAsync(IdentityActionToken action, string? password, CancellationToken cancellationToken)
    {
        return await employees.Database.CreateExecutionStrategy().ExecuteAsync(async () =>
        {
            await using var identity = NewEmployees();
            await using var transaction = await identity.Database.BeginTransactionAsync(cancellationToken);
            var row = await LockIdentityAsync(identity, action.IdentityId, cancellationToken);
            var existing = await identity.RecoveryEffects.AsNoTracking().SingleOrDefaultAsync(x => x.ActionId == action.Id, cancellationToken);
            if (existing is not null) return existing;
            if (row is null || row.NormalizedEmail != action.BoundNormalizedEmail || row.SecurityStamp != action.BoundSecurityStamp || string.IsNullOrWhiteSpace(row.SecurityStamp)) return null;
            var outstanding = await identity.RecoveryEffects.AnyAsync(x => x.IdentityId == row.Id && x.FinalizedAcknowledgedAt == null, cancellationToken);
            // Lock waits/database retries can outlive the preliminary check. Expiry gates only a NEW effect,
            // at the fresh under-lock boundary after awaited reads; a committed receipt above still finalizes.
            if (action.ExpiresAt <= timeProvider.GetUtcNow()) return null;
            if (outstanding) throw new EmployeeRecoveryUnavailableException();
            var before = row.SecurityStamp;
            if (action.Purpose == PasswordReset)
            {
                if (password is null || !AdministrativePasswordPolicy.Accepts(password)) return null;
                row.PasswordHash = passwordHasher.HashPassword(row, password);
                row.AccessFailedCount = 0;
                row.LockoutEnd = null;
            }
            else if (action.Purpose == EmailConfirmation) row.EmailConfirmed = true;
            else return null;
            row.SecurityStamp = Guid.NewGuid().ToString();
            row.ConcurrencyStamp = Guid.NewGuid().ToString();
            var receipt = new EmployeeRecoveryEffect
            {
                ActionId = action.Id,
                TokenSha256 = action.OriginalTokenSha256!,
                Purpose = action.Purpose,
                OwnerSubject = action.OwnerSubject!,
                IdentityId = row.Id,
                NormalizedEmail = action.BoundNormalizedEmail!,
                BeforeSecurityStamp = before,
                AfterSecurityStamp = row.SecurityStamp,
                AfterConcurrencyStamp = row.ConcurrencyStamp,
                PasswordPayloadHash = action.Purpose == PasswordReset ? row.PasswordHash : null,
                AppliedAt = timeProvider.GetUtcNow(),
            };
            identity.RecoveryEffects.Add(receipt);
            await identity.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return receipt;
        });
    }

    private bool Matches(EmployeeRecoveryEffect receipt, IdentityActionToken action, string? password) =>
        MatchesBinding(receipt, action) && (receipt.Purpose == EmailConfirmation ? password is null
            : password is not null && receipt.PasswordPayloadHash is not null
                && passwordHasher.VerifyHashedPassword(new LegacyIdentityRow { Id = receipt.IdentityId }, receipt.PasswordPayloadHash, password) != PasswordVerificationResult.Failed);

    private static bool MatchesBinding(EmployeeRecoveryEffect receipt, IdentityActionToken action) =>
        action.RecoveryVersion == 1 && receipt.ActionId == action.Id && receipt.TokenSha256 == action.OriginalTokenSha256
        && receipt.OwnerSubject == action.OwnerSubject && receipt.Purpose == action.Purpose && receipt.IdentityId == action.IdentityId
        && receipt.NormalizedEmail == action.BoundNormalizedEmail && receipt.BeforeSecurityStamp == action.BoundSecurityStamp;

    private async Task FinalizeAsync(RefreshSessionDbContext auth, EmployeeRecoveryEffect receipt, CancellationToken cancellationToken)
    {
        var action = await LockActionAsync(auth, receipt.ActionId, cancellationToken);
        if (action is null || !MatchesBinding(receipt, action)) throw new EmployeeRecoveryUnavailableException();
        if (action.FinalizedAt is not null && action.EffectActionId == receipt.ActionId) return;
        if (action.ConsumedAt is not null) throw new EmployeeRecoveryUnavailableException();
        var now = timeProvider.GetUtcNow();
        if (receipt.Purpose == PasswordReset)
        {
            // Explicit NULL handling for legacy sessions; preserve later/new generations.
            await auth.RefreshSessions.Where(x => x.IdentityId == receipt.IdentityId && x.IdentityKind == IdentityKind.Employee && x.RevokedAt == null
                && (x.SecurityStamp == receipt.BeforeSecurityStamp || x.SecurityStamp == null))
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAt, now), cancellationToken);
        }
        await auth.IdentityActionTokens.Where(x => x.Id == action.Id && x.ConsumedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.ConsumedAt, now).SetProperty(x => x.FinalizedAt, now).SetProperty(x => x.EffectActionId, receipt.ActionId), cancellationToken);
    }

    public async Task<int> ReconcileOutstandingAsync(CancellationToken cancellationToken)
    {
        await EnsureReadyAsync(cancellationToken);
        await using var reader = NewEmployees();
        var receipts = await reader.RecoveryEffects.AsNoTracking().Where(x => x.FinalizedAcknowledgedAt == null).OrderBy(x => x.AppliedAt).Take(32).ToListAsync(cancellationToken);
        var completed = 0;
        foreach (var receipt in receipts)
        {
            await state.Database.CreateExecutionStrategy().ExecuteAsync(async () =>
            {
                await using var auth = NewState();
                await using var transaction = await auth.Database.BeginTransactionAsync(cancellationToken);
                await LockCoordinatorAsync(auth, receipt.IdentityId, cancellationToken);
                await FinalizeAsync(auth, receipt, cancellationToken);
                await transaction.CommitAsync(cancellationToken);
            });
            await AcknowledgeAsync(receipt.ActionId, cancellationToken);
            completed++;
        }
        return completed;
    }

    internal async Task<EmployeeRecoveryBatchResult> ReconcileWorkerBatchAsync(EmployeeRecoveryScanCursor cursor, CancellationToken cancellationToken)
    {
        await EnsureReadyAsync(cancellationToken);
        await using var reader = NewEmployees();
        if (cursor.Upper is null)
        {
            var upperRow = await reader.RecoveryEffects.AsNoTracking().Where(x => x.FinalizedAcknowledgedAt == null)
                .OrderByDescending(x => x.AppliedAt).ThenByDescending(x => x.ActionId)
                .Select(x => new { x.AppliedAt, x.ActionId }).FirstOrDefaultAsync(cancellationToken);
            if (upperRow is null) { cursor.Reset(); return new(0, 0); }
            cursor.Upper = new(upperRow.AppliedAt, upperRow.ActionId);
        }
        var upper = cursor.Upper.Value;
        // PostgreSQL owns timestamp/UUID ordering. Do not compare Guid bytes/order in .NET
        // or use OFFSET over a pending set that concurrent acknowledgments can shrink.
        var query = cursor.After is { } after
            ? reader.RecoveryEffects.FromSqlInterpolated($"""
                SELECT * FROM "EmployeeRecoveryEffects"
                WHERE "FinalizedAcknowledgedAt" IS NULL
                  AND ("AppliedAt", "ActionId") > ({after.AppliedAt}, {after.ActionId})
                  AND ("AppliedAt", "ActionId") <= ({upper.AppliedAt}, {upper.ActionId})
                ORDER BY "AppliedAt", "ActionId" LIMIT 32
                """)
            : reader.RecoveryEffects.FromSqlInterpolated($"""
                SELECT * FROM "EmployeeRecoveryEffects"
                WHERE "FinalizedAcknowledgedAt" IS NULL
                  AND ("AppliedAt", "ActionId") <= ({upper.AppliedAt}, {upper.ActionId})
                ORDER BY "AppliedAt", "ActionId" LIMIT 32
                """);
        var receipts = await query.AsNoTracking().ToListAsync(cancellationToken);
        if (receipts.Count == 0) { cursor.Reset(); return new(0, 0); }
        var completed = 0;
        var failed = 0;
        foreach (var receipt in receipts)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var needsAcknowledgment = await state.Database.CreateExecutionStrategy().ExecuteAsync(async () =>
                {
                    await using var auth = NewState();
                    await using var transaction = await auth.Database.BeginTransactionAsync(cancellationToken);
                    await LockCoordinatorAsync(auth, receipt.IdentityId, cancellationToken);
                    // Fresh identity-side proof; no identity row lock is held while acquiring Auth state.
                    await using var identity = NewEmployees();
                    var current = await identity.RecoveryEffects.AsNoTracking().SingleOrDefaultAsync(x => x.ActionId == receipt.ActionId, cancellationToken);
                    if (current is null || !SameImmutableReceipt(current, receipt)) throw new EmployeeRecoveryUnavailableException();
                    if (current.FinalizedAcknowledgedAt is not null) return false;
                    await FinalizeAsync(auth, current, cancellationToken);
                    await transaction.CommitAsync(cancellationToken);
                    return true;
                });
                if (needsAcknowledgment)
                {
                    await using var identity = NewEmployees();
                    var changed = await identity.RecoveryEffects.Where(x => x.ActionId == receipt.ActionId && x.FinalizedAcknowledgedAt == null)
                        .ExecuteUpdateAsync(s => s.SetProperty(x => x.FinalizedAcknowledgedAt, timeProvider.GetUtcNow()), cancellationToken);
                    if (changed == 1) completed++;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch
            {
                // The receipt-local transaction/contexts have unwound before proceeding. Unknown
                // commit/teardown/ack outcomes remain pending; only a later fresh proof may acknowledge.
                cancellationToken.ThrowIfCancellationRequested();
                failed++;
            }
            cancellationToken.ThrowIfCancellationRequested();
            cursor.After = new(receipt.AppliedAt, receipt.ActionId);
        }
        if (cursor.After == cursor.Upper) cursor.Reset();
        return new(completed, failed);
    }

    private static bool SameImmutableReceipt(EmployeeRecoveryEffect left, EmployeeRecoveryEffect right) =>
        left.ActionId == right.ActionId && left.AppliedAt == right.AppliedAt && left.TokenSha256 == right.TokenSha256
        && left.Purpose == right.Purpose && left.OwnerSubject == right.OwnerSubject && left.IdentityId == right.IdentityId
        && left.NormalizedEmail == right.NormalizedEmail && left.BeforeSecurityStamp == right.BeforeSecurityStamp
        && left.AfterSecurityStamp == right.AfterSecurityStamp && left.AfterConcurrencyStamp == right.AfterConcurrencyStamp
        && left.PasswordPayloadHash == right.PasswordPayloadHash;

    private async Task AcknowledgeAsync(Guid actionId, CancellationToken cancellationToken)
    {
        await using var fresh = NewEmployees();
        await fresh.RecoveryEffects.Where(x => x.ActionId == actionId && x.FinalizedAcknowledgedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.FinalizedAcknowledgedAt, timeProvider.GetUtcNow()), cancellationToken);
    }

    internal static async Task LockCoordinatorAsync(RefreshSessionDbContext auth, string identityId, CancellationToken cancellationToken) =>
        await auth.Database.ExecuteSqlInterpolatedAsync($"SELECT pg_advisory_xact_lock(hashtextextended({"employee-recovery:" + identityId}, 0))", cancellationToken);
    internal static Task<LegacyIdentityRow?> LockIdentityAsync(EmployeeIdentityDbContext identity, string id, CancellationToken cancellationToken) =>
        identity.Users.FromSqlInterpolated($"SELECT * FROM \"AspNetUsers\" WHERE \"Id\" = {id} FOR UPDATE").SingleOrDefaultAsync(cancellationToken);
    private static Task<IdentityActionToken?> LockActionAsync(RefreshSessionDbContext auth, Guid id, CancellationToken cancellationToken) =>
        auth.IdentityActionTokens.FromSqlInterpolated($"SELECT * FROM identity_action_tokens WHERE \"Id\" = {id} FOR UPDATE").AsNoTracking().SingleOrDefaultAsync(cancellationToken);
    private static bool ValidOwner(string owner) => !string.IsNullOrWhiteSpace(owner) && owner.Length <= 256;
    private static string Normalize(string email) => email.Trim().ToUpperInvariant();
    private static string HashToken(string token) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
    private static string HashBoundToken(string token, string stamp, string email) => HashToken($"{token}:{stamp}:{email}");
}
