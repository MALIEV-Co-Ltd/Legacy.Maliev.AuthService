using System.Globalization;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>
/// Lossless prospective mapping for SQL Server datetimeoffset(7). This is not
/// wired to the current production identity column until its schema is reviewed.
/// </summary>
public static class LockoutEndExactText
{
    private const string Pattern = "yyyy-MM-dd'T'HH:mm:ss.fffffffzzz";

    /// <summary>Converts a nullable lockout end to and from canonical text.</summary>
    public static ValueConverter<DateTimeOffset?, string?> Converter { get; } = new(
        value => Format(value),
        value => Parse(value));

    /// <summary>Formats a value without losing its original offset or 100 ns digit.</summary>
    public static string? Format(DateTimeOffset? value) =>
        value?.ToString(Pattern, CultureInfo.InvariantCulture);

    /// <summary>Parses only the canonical seven-digit offset-bearing form.</summary>
    /// <exception cref="FormatException">The value is not canonical datetimeoffset text.</exception>
    public static DateTimeOffset? Parse(string? value)
    {
        if (value is null)
        {
            return null;
        }

        if (!DateTimeOffset.TryParseExact(value, Pattern, CultureInfo.InvariantCulture,
                DateTimeStyles.None, out var parsed)
            || !string.Equals(Format(parsed), value, StringComparison.Ordinal))
        {
            throw new FormatException("LockoutEnd exact text is not a canonical datetimeoffset(7) value.");
        }

        return parsed;
    }
}
