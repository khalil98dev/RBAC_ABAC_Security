using SecurityBuilder.Abstractions;

namespace SecurityBuilder.Common;

/// <summary>
/// Answers from the cache first and asks the real store only for the role names it does not have.
/// It wraps whichever store is registered, so replacing the store - or the cache - changes nothing else.
/// </summary>
public sealed class CachedRolePermissionStore(IRolePermissionStore inner, RolePermissionCache cache)
    : IRolePermissionStore
{
    public async Task<IReadOnlyCollection<Role>> GetRolesAsync(
        IEnumerable<string> roleNames,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(roleNames);

        List<Role> roles = [];
        List<string> missing = [];

        foreach (var name in roleNames)
        {
            if (cache.TryGet(name, out var cached) && cached is not null)
                roles.Add(cached);
            else
                missing.Add(name);
        }

        if (missing.Count == 0)
            return roles;

        foreach (var role in await inner.GetRolesAsync(missing, cancellationToken))
        {
            cache.Set(role);
            roles.Add(role);
        }

        return roles;
    }
}
