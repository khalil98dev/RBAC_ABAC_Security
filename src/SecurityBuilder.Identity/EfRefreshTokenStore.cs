using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;

namespace SecurityBuilder.Identity;

/// <summary>
/// Refresh tokens in the application's own database. The model has to be mapped with
/// <c>ApplyIdentityModel</c>.
/// </summary>
public sealed class EfRefreshTokenStore<TContext>(TContext context, TimeProvider clock) : IRefreshTokenStore
    where TContext : DbContext
{
    public async Task AddAsync(RefreshToken token, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);

        context.Add(token);

        await context.SaveChangesAsync(cancellationToken);
    }

    public Task<RefreshToken?> FindAsync(string tokenHash, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenHash);

        return context.Set<RefreshToken>()
            .SingleOrDefaultAsync(token => token.TokenHash == tokenHash, cancellationToken);
    }

    public async Task RotateAsync(
        RefreshToken used,
        RefreshToken replacement,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(used);
        ArgumentNullException.ThrowIfNull(replacement);

        context.Update(used);
        context.Add(replacement);

        // One save: a crash must not be able to leave the old token live beside its replacement.
        await context.SaveChangesAsync(cancellationToken);
    }

    public Task RevokeFamilyAsync(Guid familyId, CancellationToken cancellationToken = default) =>
        Revoke(token => token.FamilyId == familyId, cancellationToken);

    public Task RevokeUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);

        return Revoke(token => token.UserId == userId, cancellationToken);
    }

    // ExecuteUpdate on purpose: a family can be long and none of it needs loading. It bypasses the
    // change tracker, which is the known hole for secured resources - a refresh token is not one, and
    // revoking runs before anyone is signed in.
    private Task<int> Revoke(
        Expression<Func<RefreshToken, bool>> match,
        CancellationToken cancellationToken)
    {
        var now = clock.GetUtcNow();

        return context.Set<RefreshToken>()
            .Where(match)
            .Where(token => token.RevokedAt == null)
            .ExecuteUpdateAsync(set => set.SetProperty(token => token.RevokedAt, now), cancellationToken);
    }
}
