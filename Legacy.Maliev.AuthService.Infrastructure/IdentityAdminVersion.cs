using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.AuthService.Infrastructure;

internal static class IdentityAdminVersion
{
    internal static string Get(LegacyIdentityRow user) => Convert.ToHexString(
        SHA256.HashData(Encoding.UTF8.GetBytes(user.Id + "\0" + (user.ConcurrencyStamp ?? string.Empty))));
    internal static bool Matches(LegacyIdentityRow user, string expected) =>
        string.Equals(expected, "\"" + Get(user) + "\"", StringComparison.Ordinal);
}
