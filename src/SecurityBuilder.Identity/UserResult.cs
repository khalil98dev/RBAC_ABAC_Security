using SecurityBuilder.Grants;

namespace SecurityBuilder.Identity;

/// <summary>
/// The outcome of creating a user: the user, or every reason it was refused - the same all-errors
/// shape as grant validation (R7), so an admin UI shows them together.
/// </summary>
public sealed class UserResult
{
    private UserResult(User? user, IReadOnlyList<SecurityError> errors)
    {
        User = user;
        Errors = errors;
    }

    public User? User { get; }

    public IReadOnlyList<SecurityError> Errors { get; }

    public bool Succeeded => Errors.Count == 0;

    internal static UserResult Success(User user) => new(user, []);

    internal static UserResult Failure(IReadOnlyList<SecurityError> errors) => new(null, errors);
}
