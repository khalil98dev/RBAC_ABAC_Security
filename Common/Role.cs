using TestPermissions.Permissions;

namespace TestPermissions.Common;

public class Role
{
    private HashSet<ResourcePermission> _resourcePermissions { get; set; } = [];
    public Guid RoleId { get; set; }
    public string RoleName { get; set; } = default!;
    public string Description { get; set; } = default!;

    public IReadOnlyCollection<ResourcePermission> ResourcePermissions
       => _resourcePermissions.AsReadOnly();

    private Role() { }


    private Role(string RoleName, string Description)
    {
        RoleId = Guid.CreateVersion7();
        this.RoleName = RoleName;
        this.Description = Description;
    }

    public static Role CreateRole(string RoleName, string Description)
    {
        return new(RoleName, Description);
    }


    public void AddResourcePermission(ResourcePermission permission)
    {
        ArgumentNullException.ThrowIfNull(permission);

        if (permission.RoleId != RoleId)
        {
            throw new InvalidOperationException("The resource permission belongs to a different role.");
        }

        if (_resourcePermissions.Any(p =>
                p.ResourcePermissionId == permission.ResourcePermissionId ||
                string.Equals(p.Resource, permission.Resource, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException($"A permission for resource '{permission.Resource}' already exists.");
        }

        _resourcePermissions.Add(permission);
    }

    public bool RemoveResourcePermission(Guid resourcePermissionId)
    {
        var permission = _resourcePermissions.SingleOrDefault(p => p.ResourcePermissionId == resourcePermissionId);

        return permission is not null && _resourcePermissions.Remove(permission);
    }

    // Validation of incoming permissions against the SecurityRegistry is still to be designed.
    // The registry is passed in (or used by a domain service) rather than stored on the Role.
}
