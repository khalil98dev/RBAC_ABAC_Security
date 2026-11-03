using SecurityBuilder.Tokens;

namespace SecurityBuilder.Abstractions;

/// <summary>
/// Where a user's name, email and role names come from when a token is refreshed. This is the seam
/// that keeps the token service out of the user store: implement it over the users package, over
/// ASP.NET Core Identity, or over anything else.
/// </summary>
public interface ITokenSubjectProvider
{
    Task<TokenSubject?> FindAsync(string userId, CancellationToken cancellationToken = default);
}
