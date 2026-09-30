using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using System.Data;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Read-only physical schema checks; migration history alone is not a safety gate.</summary>
public static class EmployeeRecoverySchema
{
    public static async Task EnsureAsync(EmployeeIdentityDbContext employees, RefreshSessionDbContext state, CancellationToken cancellationToken)
    {
        try
        {
            await EnsureEmployeeAsync(employees, cancellationToken);
            await VerifyEntityAsync(state, typeof(Legacy.Maliev.AuthService.Domain.IdentityActionToken), cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { throw new EmployeeRecoveryUnavailableException(); }
    }

    public static async Task EnsureEmployeeAsync(EmployeeIdentityDbContext employees, CancellationToken cancellationToken)
    {
        try { await VerifyEntityAsync(employees, typeof(EmployeeRecoveryEffect), cancellationToken); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { throw new EmployeeRecoveryUnavailableException(); }
    }

    private static async Task VerifyEntityAsync(DbContext context, Type type, CancellationToken cancellationToken)
    {
        var entity = context.GetService<IDesignTimeModel>().Model.FindEntityType(type)!;
        var table = entity.GetTableName()!;
        var identifier = StoreObjectIdentifier.Table(table, entity.GetSchema());
        var connection = context.Database.GetDbConnection();
        if (connection.State != ConnectionState.Open) await context.Database.OpenConnectionAsync(cancellationToken);
        foreach (var property in entity.GetProperties())
        {
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT format_type(a.atttypid,a.atttypmod), a.attnotnull FROM pg_attribute a WHERE a.attrelid=to_regclass(@table) AND a.attname=@column AND a.attnum>0 AND NOT a.attisdropped";
            Add(command, "table", '"' + table + '"');
            Add(command, "column", property.GetColumnName(identifier)!);
            await using var result = await command.ExecuteReaderAsync(cancellationToken);
            if (!await result.ReadAsync(cancellationToken) || result.GetString(0) != property.GetColumnType() || result.GetBoolean(1) == property.IsNullable)
                throw new EmployeeRecoveryUnavailableException();
        }
        foreach (var index in entity.GetIndexes())
        {
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT i.indisunique, i.indisvalid, i.indisready, ARRAY(SELECT a.attname FROM unnest(i.indkey) WITH ORDINALITY k(attnum,n) JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum ORDER BY n), i.indpred IS NULL AND i.indexprs IS NULL AND i.indnkeyatts=i.indnatts AND NOT i.indnullsnotdistinct AND am.amname='btree' FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_am am ON am.oid=c.relam WHERE i.indrelid=to_regclass(@table) AND c.relname=@name";
            Add(command, "table", '"' + table + '"');
            Add(command, "name", index.GetDatabaseName()!);
            await using var result = await command.ExecuteReaderAsync(cancellationToken);
            if (!await result.ReadAsync(cancellationToken) || result.GetBoolean(0) != index.IsUnique || !result.GetBoolean(1) || !result.GetBoolean(2)
                || !result.GetFieldValue<string[]>(3).SequenceEqual(index.Properties.Select(x => x.GetColumnName(identifier))) || !result.GetBoolean(4)) throw new EmployeeRecoveryUnavailableException();
        }
        foreach (var constraint in entity.GetCheckConstraints())
        {
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT convalidated, pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid=to_regclass(@table) AND conname=@name AND contype='c'";
            Add(command, "table", '"' + table + '"');
            Add(command, "name", constraint.Name!);
            await using var result = await command.ExecuteReaderAsync(cancellationToken);
            if (!await result.ReadAsync(cancellationToken) || !result.GetBoolean(0)) throw new EmployeeRecoveryUnavailableException();
            // Exact reviewed PostgreSQL catalog expressions preserve boolean grouping; a marker check would
            // accept a weakened original-expression OR 1=1 constraint. Unknown renderings fail closed.
            if (result.GetString(1) != ReviewedConstraint(constraint.Name!)) throw new EmployeeRecoveryUnavailableException();
        }
        await using var primaryKey = connection.CreateCommand();
        primaryKey.CommandText = "SELECT convalidated, ARRAY(SELECT a.attname FROM unnest(c.conkey) WITH ORDINALITY k(attnum,n) JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum ORDER BY n) FROM pg_constraint c WHERE c.conrelid=to_regclass(@table) AND c.contype='p'";
        Add(primaryKey, "table", '"' + table + '"');
        await using var keyResult = await primaryKey.ExecuteReaderAsync(cancellationToken);
        if (!await keyResult.ReadAsync(cancellationToken) || !keyResult.GetBoolean(0)
            || !keyResult.GetFieldValue<string[]>(1).SequenceEqual(entity.FindPrimaryKey()!.Properties.Select(x => x.GetColumnName(identifier)))) throw new EmployeeRecoveryUnavailableException();
    }

    private static string ReviewedConstraint(string name) => name switch
    {
        "CK_EmployeeRecoveryEffects_Binding" => "CHECK (((length((\"TokenSha256\")::text) = 64) AND (length((\"OwnerSubject\")::text) > 0) AND (length(\"BeforeSecurityStamp\") > 0) AND (length(\"AfterSecurityStamp\") > 0)))",
        "CK_EmployeeRecoveryEffects_PurposePayload" => "CHECK (((((\"Purpose\")::text = 'employee-password-reset'::text) AND (\"PasswordPayloadHash\" IS NOT NULL)) OR (((\"Purpose\")::text = 'employee-email-confirmation'::text) AND (\"PasswordPayloadHash\" IS NULL))))",
        "CK_identity_action_tokens_employee_binding" => "CHECK (((\"RecoveryVersion\" IS NULL) OR ((\"RecoveryVersion\" = 1) AND ((\"Purpose\")::text = ANY ((ARRAY['employee-password-reset'::character varying, 'employee-email-confirmation'::character varying])::text[])) AND (\"OriginalTokenSha256\" IS NOT NULL) AND (length((\"OriginalTokenSha256\")::text) = 64) AND (\"OwnerSubject\" IS NOT NULL) AND (length((\"OwnerSubject\")::text) > 0) AND (\"BoundNormalizedEmail\" IS NOT NULL) AND (length((\"BoundNormalizedEmail\")::text) > 0) AND (\"BoundSecurityStamp\" IS NOT NULL) AND (length(\"BoundSecurityStamp\") > 0))))",
        "CK_identity_action_tokens_employee_finalization" => "CHECK ((((\"FinalizedAt\" IS NULL) AND (\"EffectActionId\" IS NULL)) OR ((\"RecoveryVersion\" IS NOT NULL) AND (\"RecoveryVersion\" = 1) AND (\"FinalizedAt\" IS NOT NULL) AND (\"ConsumedAt\" IS NOT NULL) AND (\"EffectActionId\" IS NOT NULL) AND (\"EffectActionId\" = \"Id\"))))",
        _ => throw new EmployeeRecoveryUnavailableException(),
    };

    private static void Add(System.Data.Common.DbCommand command, string name, string value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value;
        command.Parameters.Add(parameter);
    }
}

public sealed class EmployeeRecoveryHealthCheck(EmployeeIdentityDbContext employees, RefreshSessionDbContext state, EmployeeRecoveryOptions options) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        if (!options.Enabled) return HealthCheckResult.Unhealthy("Employee recovery requires coordinated rollout opt-in.");
        try
        {
            await EmployeeRecoverySchema.EnsureAsync(employees, state, cancellationToken);
            return HealthCheckResult.Healthy();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return HealthCheckResult.Unhealthy("Employee recovery schema is unavailable."); }
    }
}
