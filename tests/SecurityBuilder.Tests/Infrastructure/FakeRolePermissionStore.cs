using SecurityBuilder.Abstractions;
using SecurityBuilder.Common;

namespace SecurityBuilder.Tests.Infrastructure;

/// <summary>A role store that answers from memory and records what it was asked for.</summary>
internal sealed class FakeRolePermissionStore(params Role[] roles) : IRolePermissionStore
{
    public List<string> Asked { get; } = [];

    public int Calls { get; private set; }

    public Task<IReadOnlyCollection<Role>> GetRolesAsync(
        IEnumerable<string> roleNames,
        CancellationToken cancellationToken = default)
    {
        Calls++;

        var names = roleNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
        Asked.AddRange(names);

        return Task.FromResult<IReadOnlyCollection<Role>>(
            roles.Where(role => names.Contains(role.RoleName)).ToList());
    }
}
