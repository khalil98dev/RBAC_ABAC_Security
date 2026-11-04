namespace SecurityBuilder.Abstractions;

/// <summary>
/// An <see cref="ICurrentUser"/> that does not come from a request: <see cref="Anonymous"/> for an
/// unauthenticated caller and <see cref="System"/> for seeding, migrations and background jobs, where
/// <c>SecurityContext.RunAsSystem</c> is in charge and audit fields still need an author.
/// </summary>
public sealed class StaticCurrentUser(
    string? userId,
    string? userName,
    string? email,
    bool isAuthenticated,
    IReadOnlyCollection<string> roles) : ICurrentUser
{
    public static ICurrentUser Anonymous { get; } = new StaticCurrentUser(null, null, null, false, []);

    public static ICurrentUser System { get; } = new StaticCurrentUser("system", "system", null, true, []);

    public string? UserId => userId;

    public string? UserName => userName;

    public string? Email => email;

    public bool IsAuthenticated => isAuthenticated;

    public IReadOnlyCollection<string> Roles => roles;
}
