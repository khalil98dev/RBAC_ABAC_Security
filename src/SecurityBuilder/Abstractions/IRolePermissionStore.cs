using SecurityBuilder.Common;

namespace SecurityBuilder.Abstractions;

/// <summary>
/// Where a role's permissions come from. The token carries role names only, so something has to turn
/// those names into <see cref="Role"/> objects with their permissions; this is that something.
/// The EF Core package has an implementation, and anything else can replace it.
/// </summary>
public interface IRolePermissionStore
{
    /// <summary>
    /// The roles for these names, with their permissions loaded. Names are matched case-insensitively;
    /// a name with no role behind it is skipped rather than failing the request, because a token can
    /// outlive a role that was deleted.
    /// </summary>
    Task<IReadOnlyCollection<Role>> GetRolesAsync(IEnumerable<string> roleNames,CancellationToken cancellationToken = default);
}
