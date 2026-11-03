using SecurityBuilder.Tokens;

namespace SecurityBuilder.Abstractions;

/// <summary>
/// Issues and exchanges tokens. The interface lives in the core so application code can depend on it
/// without taking on a signing library; the implementation lives in <c>SecurityBuilder.Identity</c>
/// and is registered with <c>TryAdd</c>, so registering your own first wins.
/// </summary>
public interface ISecurityTokenService
{
    /// <summary>A fresh pair, after the caller has proved who they are.</summary>
    Task<TokenPair> IssueAsync(TokenSubject subject, CancellationToken cancellationToken = default);

    /// <summary>
    /// Exchanges a refresh token for the next pair and invalidates the one presented. The subject is
    /// read again through <see cref="ITokenSubjectProvider"/>, so a role taken away reaches the client
    /// within one access-token lifetime.
    /// </summary>
    /// <exception cref="InvalidRefreshTokenException">The token cannot be exchanged.</exception>
    Task<TokenPair> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default);

    /// <summary>Signs one session out: the token and everything rotated from it stop working.</summary>
    Task RevokeAsync(string refreshToken, CancellationToken cancellationToken = default);

    /// <summary>
    /// Signs every session of one user out. Call it when the password changes or the account is
    /// disabled - otherwise refresh tokens handed out earlier would outlive the change.
    /// </summary>
    Task RevokeAllAsync(string userId, CancellationToken cancellationToken = default);
}
