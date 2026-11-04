namespace SecurityBuilder.Tokens;

/// <summary>
/// An access token to send with every request and a refresh token to exchange for the next pair.
/// The refresh token is only ever readable here: the store keeps a hash of it.
/// </summary>
public sealed record TokenPair(
    string AccessToken,
    DateTimeOffset AccessTokenExpiresAt,
    string RefreshToken,
    DateTimeOffset RefreshTokenExpiresAt);
