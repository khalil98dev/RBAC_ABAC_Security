using SecurityBuilder.Common;

namespace SecurityBuilder.Identity;

/// <summary>
/// An account that can sign in. Membership is by role id, so deleting a role takes its members with
/// it; the role names a token carries are read through the join when the token is issued.
///
/// The password hash is set only by <see cref="UserAccountService{TContext}"/>, which owns hashing.
/// </summary>
public sealed class User
{
    private readonly HashSet<UserRole> _roles = [];

    private User()
    {
        UserName = null!;
        NormalizedUserName = null!;
        PasswordHash = null!;
    }

    private User(string userName, string? email, DateTimeOffset createdAt)
    {
        UserId = Guid.CreateVersion7();
        UserName = userName;
        NormalizedUserName = Normalize(userName);
        Email = email;
        PasswordHash = string.Empty;
        IsActive = true;
        CreatedAt = createdAt;
    }

    public Guid UserId { get; private set; }

    public string UserName { get; private set; }

    /// <summary>
    /// The user name in upper case, which is what is unique. Comparing it rather than relying on the
    /// collation keeps "Khalil" and "khalil" one account on every provider.
    /// </summary>
    public string NormalizedUserName { get; private set; }

    public string? Email { get; private set; }

    public string PasswordHash { get; private set; }

    /// <summary>False once deactivated: signing in and refreshing are refused.</summary>
    public bool IsActive { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public IReadOnlyCollection<UserRole> Roles => _roles;

    public static string Normalize(string userName) => userName.Trim().ToUpperInvariant();

    internal static User Create(string userName, string? email, DateTimeOffset createdAt) =>
        new(userName.Trim(), string.IsNullOrWhiteSpace(email) ? null : email.Trim(), createdAt);

    internal void SetPasswordHash(string passwordHash) => PasswordHash = passwordHash;

    public void AssignRole(Role role)
    {
        ArgumentNullException.ThrowIfNull(role);

        _roles.Add(new UserRole(UserId, role.RoleId));
    }

    public bool RemoveRole(Guid roleId) => _roles.RemoveWhere(membership => membership.RoleId == roleId) > 0;

    internal void Deactivate() => IsActive = false;
}

/// <summary>One user in one role.</summary>
public sealed record UserRole(Guid UserId, Guid RoleId);
