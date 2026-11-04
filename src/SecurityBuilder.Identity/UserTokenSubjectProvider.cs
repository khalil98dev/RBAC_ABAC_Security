using Microsoft.EntityFrameworkCore;
using SecurityBuilder.Abstractions;
using SecurityBuilder.Common;
using SecurityBuilder.Tokens;

namespace SecurityBuilder.Identity;

/// <summary>
/// The users package's answer to "who is this token for": the account and its role names, read fresh.
/// A deactivated or deleted account yields null, which refuses the refresh.
/// </summary>
public sealed class UserTokenSubjectProvider<TContext>(TContext context) : ITokenSubjectProvider
    where TContext : DbContext
{
    public async Task<TokenSubject?> FindAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParse(userId, out var id))
            return null;

        var user = await context.Set<User>()
            .AsNoTracking()
            .Where(account => account.UserId == id && account.IsActive)
            .Select(account => new { account.UserId, account.UserName, account.Email })
            .SingleOrDefaultAsync(cancellationToken);

        if (user is null)
            return null;

        var roles = await context.Set<UserRole>()
            .Where(membership => membership.UserId == id)
            .Join(context.Set<Role>(), membership => membership.RoleId, role => role.RoleId, (_, role) => role.RoleName)
            .ToListAsync(cancellationToken);

        return new TokenSubject(user.UserId.ToString(), user.UserName, user.Email, roles);
    }
}
