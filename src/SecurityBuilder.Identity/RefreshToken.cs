namespace SecurityBuilder.Identity;

/// <summary>
/// One link in a refresh chain. Every exchange marks the token used and adds its replacement to the
/// same family, so a token presented twice is proof that the chain leaked: the family is revoked.
///
/// Only a hash of the token is kept. A leaked table is then useless to an attacker, and nobody -
/// including an admin reading the database - can take over a session with what is stored.
/// </summary>
public sealed class RefreshToken
{
    private RefreshToken()
    {
        UserId = null!;
        TokenHash = null!;
    }

    private RefreshToken(
        Guid familyId,
        string userId,
        string tokenHash,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt,
        DateTimeOffset familyExpiresAt)
    {
        RefreshTokenId = Guid.CreateVersion7();
        FamilyId = familyId;
        UserId = userId;
        TokenHash = tokenHash;
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
        FamilyExpiresAt = familyExpiresAt;
    }

    public Guid RefreshTokenId { get; private set; }

    /// <summary>The chain this token belongs to. Revoking is always per family, never per token.</summary>
    public Guid FamilyId { get; private set; }

    public string UserId { get; private set; }

    public string TokenHash { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>The sliding expiry, moved forward on every exchange but never past the family's cap.</summary>
    public DateTimeOffset ExpiresAt { get; private set; }

    /// <summary>
    /// The absolute cap for the whole chain. Without it, a client that keeps refreshing would stay
    /// signed in for ever.
    /// </summary>
    public DateTimeOffset FamilyExpiresAt { get; private set; }

    public DateTimeOffset? UsedAt { get; private set; }

    public DateTimeOffset? RevokedAt { get; private set; }

    /// <summary>The first token of a new chain, which is what signing in hands out.</summary>
    public static RefreshToken Start(
        string userId,
        string tokenHash,
        DateTimeOffset now,
        TimeSpan lifetime,
        TimeSpan absoluteLifetime)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenHash);

        var familyExpiresAt = now + absoluteLifetime;

        return new RefreshToken(
            Guid.CreateVersion7(), userId, tokenHash, now,
            Earliest(now + lifetime, familyExpiresAt), familyExpiresAt);
    }

    /// <summary>The next token of this chain. The caller marks this one used in the same unit of work.</summary>
    public RefreshToken Rotate(string tokenHash, DateTimeOffset now, TimeSpan lifetime)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenHash);

        return new RefreshToken(
            FamilyId, UserId, tokenHash, now,
            Earliest(now + lifetime, FamilyExpiresAt), FamilyExpiresAt);
    }

    public bool IsExpired(DateTimeOffset now) => ExpiresAt <= now || FamilyExpiresAt <= now;

    public void MarkUsed(DateTimeOffset now) => UsedAt ??= now;

    public void Revoke(DateTimeOffset now) => RevokedAt ??= now;

    private static DateTimeOffset Earliest(DateTimeOffset left, DateTimeOffset right) =>
        left <= right ? left : right;
}
