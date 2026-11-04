using SecurityBuilder.Tokens;

namespace SecurityBuilder.Abstractions;
public interface ISecurityTokenService
{
    Task<TokenPair> IssueAsync(TokenSubject subject, CancellationToken cancellationToken = default);
    Task<TokenPair> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default);

    Task RevokeAsync(string refreshToken, CancellationToken cancellationToken = default);

    Task RevokeAllAsync(string userId, CancellationToken cancellationToken = default);
}
