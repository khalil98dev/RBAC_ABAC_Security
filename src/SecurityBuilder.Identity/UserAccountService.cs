using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecurityBuilder.Abstractions;
using SecurityBuilder.Common;
using SecurityBuilder.Grants;
using SecurityBuilder.Tokens;

namespace SecurityBuilder.Identity;

/// <summary>
/// Creating accounts, signing in, and the two changes that must end every session: a new password and
/// a deactivated account.
///
/// Hashing is <see cref="IPasswordHasher{TUser}"/> from <c>Microsoft.Extensions.Identity.Core</c> -
/// PBKDF2 with a versioned format - rather than anything written here, and it is replaceable through
/// DI like the rest.
/// </summary>
public sealed class UserAccountService<TContext>(
    TContext context,
    IPasswordHasher<User> hasher,
    ISecurityTokenService tokens,
    ITokenSubjectProvider subjects,
    TimeProvider clock)
    where TContext : DbContext
{
    public const int MinimumPasswordLength = 8;

    // Verified against when the user name is unknown, so a failed sign-in takes as long either way and
    // its timing does not tell which user names exist.
    private static string? _unknownUserHash;

    /// <summary>Creates an account in the named roles, or returns every reason it cannot be created.</summary>
    public async Task<UserResult> CreateAsync(
        string userName,
        string? email,
        string password,
        IEnumerable<string> roleNames,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(roleNames);

        List<SecurityError> errors = [];

        if (string.IsNullOrWhiteSpace(userName))
            errors.Add(new SecurityError("UserNameRequired", "A user name is required."));
        else if (await UserNameTaken(userName, cancellationToken))
            errors.Add(new SecurityError("UserNameTaken", $"The user name '{userName.Trim()}' is already taken."));

        if (string.IsNullOrEmpty(password) || password.Length < MinimumPasswordLength)
        {
            errors.Add(new SecurityError(
                "PasswordTooShort", $"A password needs at least {MinimumPasswordLength} characters."));
        }

        var names = roleNames.Where(name => !string.IsNullOrWhiteSpace(name)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var roles = await FindRoles(names, cancellationToken);

        foreach (var missing in names.Where(name => !roles.Any(role => string.Equals(role.RoleName, name, StringComparison.OrdinalIgnoreCase))))
            errors.Add(new SecurityError("UnknownRole", $"There is no role named '{missing}'."));

        if (errors.Count > 0)
            return UserResult.Failure(errors);

        var user = User.Create(userName, email, clock.GetUtcNow());
        user.SetPasswordHash(hasher.HashPassword(user, password));

        foreach (var role in roles)
            user.AssignRole(role);

        context.Add(user);
        await context.SaveChangesAsync(cancellationToken);

        return UserResult.Success(user);
    }

    /// <summary>
    /// A token pair for the right password, or null - for an unknown user, a wrong password and a
    /// deactivated account alike, so the answer says nothing about which it was.
    /// </summary>
    public async Task<TokenPair?> SignInAsync(
        string userName,
        string password,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(userName) || string.IsNullOrEmpty(password))
            return null;

        var normalized = User.Normalize(userName);

        var user = await context.Set<User>()
            .SingleOrDefaultAsync(account => account.NormalizedUserName == normalized, cancellationToken);

        if (user is null)
        {
            hasher.VerifyHashedPassword(User.Create("unknown", null, default), UnknownUserHash(), password);
            return null;
        }

        var verification = hasher.VerifyHashedPassword(user, user.PasswordHash, password);

        if (verification == PasswordVerificationResult.Failed || !user.IsActive)
            return null;

        // The hasher reports an older format or weaker settings: re-hash now, while the password is known.
        if (verification == PasswordVerificationResult.SuccessRehashNeeded)
        {
            user.SetPasswordHash(hasher.HashPassword(user, password));
            await context.SaveChangesAsync(cancellationToken);
        }

        var subject = await subjects.FindAsync(user.UserId.ToString(), cancellationToken);

        return subject is null ? null : await tokens.IssueAsync(subject, cancellationToken);
    }

    /// <summary>
    /// Sets a new password when the current one is right, and signs every session out: a refresh token
    /// handed out under the old password must not outlive it.
    /// </summary>
    public async Task<bool> ChangePasswordAsync(
        Guid userId,
        string currentPassword,
        string newPassword,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(newPassword) || newPassword.Length < MinimumPasswordLength)
            return false;

        var user = await context.Set<User>().SingleOrDefaultAsync(account => account.UserId == userId, cancellationToken);

        if (user is null || hasher.VerifyHashedPassword(user, user.PasswordHash, currentPassword) == PasswordVerificationResult.Failed)
            return false;

        user.SetPasswordHash(hasher.HashPassword(user, newPassword));
        await context.SaveChangesAsync(cancellationToken);

        await tokens.RevokeAllAsync(user.UserId.ToString(), cancellationToken);

        return true;
    }

    /// <summary>Stops the account signing in and ends its sessions now, not when their tokens expire.</summary>
    public async Task<bool> DeactivateAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var user = await context.Set<User>().SingleOrDefaultAsync(account => account.UserId == userId, cancellationToken);

        if (user is null)
            return false;

        user.Deactivate();
        await context.SaveChangesAsync(cancellationToken);

        await tokens.RevokeAllAsync(user.UserId.ToString(), cancellationToken);

        return true;
    }

    private Task<bool> UserNameTaken(string userName, CancellationToken cancellationToken)
    {
        var normalized = User.Normalize(userName);

        return context.Set<User>().AnyAsync(account => account.NormalizedUserName == normalized, cancellationToken);
    }

    private async Task<List<Role>> FindRoles(string[] names, CancellationToken cancellationToken)
    {
        if (names.Length == 0)
            return [];

        var upper = names.Select(name => name.ToUpper()).ToArray();

        return await context.Set<Role>()
            .Where(role => upper.Contains(role.RoleName.ToUpper()))
            .ToListAsync(cancellationToken);
    }

    private string UnknownUserHash() =>
        _unknownUserHash ??= hasher.HashPassword(User.Create("unknown", null, default), Guid.NewGuid().ToString());
}
