namespace SecurityBuilder.Tokens;

/// <summary>
/// A refresh token that cannot be exchanged: unknown, expired, already used or revoked. Answer it with
/// 401 and make the caller sign in again. It is an exception rather than a result so that a caller
/// cannot forget to check, the same reason <see cref="AccessDeniedException"/> is one.
/// </summary>
public sealed class InvalidRefreshTokenException(string message) : Exception(message);
