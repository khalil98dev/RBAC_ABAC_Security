using SecurityBuilder.Identity;

namespace SecurityBuilder.Tests.Infrastructure;

/// <summary>
/// The EF refresh token store with a context of its own per call, the way a web request gets one.
/// It is what makes the tests realistic: the token a refresh reads back was loaded by a different
/// context from the one that wrote it, so nothing can quietly rely on the change tracker.
/// </summary>
internal sealed class ScopedRefreshTokenStore(TestDatabase database, TimeProvider clock) : IRefreshTokenStore
{
    public async Task AddAsync(RefreshToken token, CancellationToken cancellationToken = default)
    {
        await using var db = database.Open(TestSecurity.Context());

        await Store(db).AddAsync(token, cancellationToken);
    }

    public async Task<RefreshToken?> FindAsync(string tokenHash, CancellationToken cancellationToken = default)
    {
        await using var db = database.Open(TestSecurity.Context());

        return await Store(db).FindAsync(tokenHash, cancellationToken);
    }

    public async Task RotateAsync(
        RefreshToken used,
        RefreshToken replacement,
        CancellationToken cancellationToken = default)
    {
        await using var db = database.Open(TestSecurity.Context());

        await Store(db).RotateAsync(used, replacement, cancellationToken);
    }

    public async Task RevokeFamilyAsync(Guid familyId, CancellationToken cancellationToken = default)
    {
        await using var db = database.Open(TestSecurity.Context());

        await Store(db).RevokeFamilyAsync(familyId, cancellationToken);
    }

    public async Task RevokeUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        await using var db = database.Open(TestSecurity.Context());

        await Store(db).RevokeUserAsync(userId, cancellationToken);
    }

    private EfRefreshTokenStore<AppDbContext> Store(AppDbContext db) => new(db, clock);
}
