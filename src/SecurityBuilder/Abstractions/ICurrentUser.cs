namespace SecurityBuilder.Abstractions;

/// <summary>
/// Who the caller is. This is the identity view, kept apart from <see cref="SecurityContext"/>, which is
/// the authorization view: use this one for audit fields, that one to decide what may be done.
/// It is deliberately claim-shaped, so the same code works behind a hand-written JWT, ASP.NET Core
/// Identity or an external provider.
/// </summary>
public interface ICurrentUser
{
    /// <summary>The user's stable id, or null when nobody is signed in.</summary>
    string? UserId { get; }

    string? UserName { get; }

    string? Email { get; }

    /// <summary>False for an anonymous caller and outside a request, so it is never a surprise null.</summary>
    bool IsAuthenticated { get; }

    /// <summary>The role names the caller presented. Their permissions live in the security context.</summary>
    IReadOnlyCollection<string> Roles { get; }
}
