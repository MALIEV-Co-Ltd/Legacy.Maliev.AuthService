namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>
/// Prospective source-backed sidecar contract. This is not mapped by either live identity context.
/// </summary>
public static class LockoutEndExactTransition
{
    /// <summary>
    /// Returns whether an incomplete row may be populated from the authoritative source.
    /// A completed null value is distinct from a row that has not been backfilled.
    /// </summary>
    public static bool NeedsBackfill(bool complete, string? storedText, DateTimeOffset? sourceValue)
    {
        if (complete)
        {
            _ = LockoutEndExactText.Parse(storedText);
            if (!string.Equals(storedText, LockoutEndExactText.Format(sourceValue), StringComparison.Ordinal))
            {
                throw new InvalidOperationException("The completed lockout sidecar conflicts with the source value.");
            }

            return false;
        }

        if (storedText is not null)
        {
            throw new InvalidOperationException("An incomplete lockout sidecar already contains a value.");
        }

        return true;
    }

    /// <summary>Reads only a completed exact source value; malformed text fails closed.</summary>
    public static DateTimeOffset? ReadCompleted(bool complete, string? storedText)
    {
        if (!complete)
        {
            throw new InvalidOperationException("The lockout sidecar has not been backfilled.");
        }

        return LockoutEndExactText.Parse(storedText);
    }
}
