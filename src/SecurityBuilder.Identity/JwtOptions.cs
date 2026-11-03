using System.Security.Claims;
using System.Text;

namespace SecurityBuilder.Identity;

/// <summary>
/// What the tokens are signed with and how long they live. The claim types default to the ones
/// <c>SecurityBuilderOptions</c> reads, so a token issued here signs in through the middleware
/// unchanged; change one side and change the other.
/// </summary>
public sealed class JwtOptions
{
    /// <summary>
    /// The signing key, from configuration or user-secrets. There is deliberately no default: a
    /// hard-coded key in a library is a key every deployment shares.
    /// </summary>
    public string SigningKey { get; set; } = string.Empty;

    public string Issuer { get; set; } = string.Empty;

    public string Audience { get; set; } = string.Empty;

    /// <summary>Short on purpose: a permission taken away reaches the client when this runs out.</summary>
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>How long one refresh token lasts. Moved forward on every exchange.</summary>
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(14);

    /// <summary>How long a chain may be refreshed at all, however active the client is.</summary>
    public TimeSpan RefreshTokenAbsoluteLifetime { get; set; } = TimeSpan.FromDays(30);

    public string UserIdClaimType { get; set; } = ClaimTypes.NameIdentifier;

    public string UserNameClaimType { get; set; } = ClaimTypes.Name;

    public string EmailClaimType { get; set; } = ClaimTypes.Email;

    public string RoleClaimType { get; set; } = ClaimTypes.Role;

    /// <summary>The smallest key HMAC-SHA256 may be used with: 256 bits.</summary>
    public const int MinimumSigningKeyBytes = 32;

    /// <summary>Checked once, when the token service is first resolved.</summary>
    public void EnsureValid()
    {
        if (string.IsNullOrWhiteSpace(SigningKey))
        {
            throw new InvalidOperationException(
                "No JWT signing key is configured. Put one in user-secrets or configuration " +
                "(for example \"Jwt:SigningKey\"); it must never be hard-coded.");
        }

        if (Encoding.UTF8.GetByteCount(SigningKey) < MinimumSigningKeyBytes)
        {
            throw new InvalidOperationException(
                $"The JWT signing key is too short: HMAC-SHA256 needs at least " +
                $"{MinimumSigningKeyBytes} bytes.");
        }

        if (string.IsNullOrWhiteSpace(Issuer))
            throw new InvalidOperationException("No JWT issuer is configured.");

        if (string.IsNullOrWhiteSpace(Audience))
            throw new InvalidOperationException("No JWT audience is configured.");

        if (AccessTokenLifetime <= TimeSpan.Zero || RefreshTokenLifetime <= TimeSpan.Zero)
            throw new InvalidOperationException("Token lifetimes must be positive.");

        if (RefreshTokenAbsoluteLifetime < RefreshTokenLifetime)
        {
            throw new InvalidOperationException(
                "The absolute refresh lifetime cannot be shorter than one refresh token's lifetime.");
        }
    }
}
