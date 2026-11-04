namespace SecurityBuilder.Tokens;

/// <summary>
/// Who a token is for. Role names only: their permissions are looked up per request, so they are
/// never written into a token.
/// </summary>
public sealed record TokenSubject(
    string UserId,
    string? UserName,
    string? Email,
    IReadOnlyCollection<string> Roles);
