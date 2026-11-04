namespace SecurityBuilder.Identity;

/// <summary>
/// Where refresh tokens live. Each method is a whole unit of work, so no caller has to remember to
/// save - and rotation in particular has to be one save, or a crash could leave two live tokens.
/// </summary>
public interface IRefreshTokenStore
{
    Task AddAsync(RefreshToken token, CancellationToken cancellationToken = default);

    /// <summary>The token with this hash, used or revoked ones included: that is how reuse is spotted.</summary>
    Task<RefreshToken?> FindAsync(string tokenHash, CancellationToken cancellationToken = default);

    /// <summary>Marks the presented token used and stores its replacement, in one save.</summary>
    Task RotateAsync(
        RefreshToken used,
        RefreshToken replacement,
        CancellationToken cancellationToken = default);

    Task RevokeFamilyAsync(Guid familyId, CancellationToken cancellationToken = default);

    Task RevokeUserAsync(string userId, CancellationToken cancellationToken = default);
}
