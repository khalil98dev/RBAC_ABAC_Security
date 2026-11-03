using Microsoft.EntityFrameworkCore;
using SecurityBuilder.Abstractions;
using SecurityBuilder.Common;

namespace SecurityBuilder.EntityFrameworkCore;

/// <summary>
/// Loads roles and their permissions from the database. The model has to be mapped with
/// <c>ApplySecurityModel</c>, which auto-includes the permissions, so loading a role gives the
/// whole aggregate.
///
/// Read with <c>AsNoTracking</c>: these roles are handed to the evaluator and may be cached, so they
/// must not be attached to the context that loaded them.
/// </summary>
public sealed class RolePermissionStore<TContext>(TContext context) : IRolePermissionStore
    where TContext : DbContext
{
    public async Task<IReadOnlyCollection<Role>> GetRolesAsync(
        IEnumerable<string> roleNames,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(roleNames);

        var names = roleNames
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Select(name => name.ToUpper())
            .ToArray();

        if (names.Length == 0)
            return [];

        // Compared in upper case rather than relying on the database collation, which is case-sensitive
        // on some providers and not on others. A role table is small and the result is cached, so the
        // unused index costs nothing. A name with no row behind it simply yields nothing.
        return await context.Set<Role>()
            .AsNoTracking()
            .Where(role => names.Contains(role.RoleName.ToUpper()))
            .ToListAsync(cancellationToken);
    }
}
