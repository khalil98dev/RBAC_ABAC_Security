using SecurityBuilder.Actions;
using SecurityBuilder.Grants;
using SecurityBuilder.Permissions;

namespace SecurityBuilder.Common;

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

    /// <summary>
    /// Replaces this role's permissions with the given grants, after validating them against the registry.
    /// If any grant is invalid, all errors are returned and the role is left unchanged.
    /// </summary>
    public SecurityValidationResult ApplyPermissions(IEnumerable<PermissionGrant> grants, SecurityRegistry registry)
    {
        ArgumentNullException.ThrowIfNull(grants);
        ArgumentNullException.ThrowIfNull(registry);

        var grantList = grants.ToList();

        var result = registry.ValidateGrants(grantList);
        if (!result.IsValid)
            return result;

        _resourcePermissions.Clear();

        foreach (var grant in grantList)
        {
            var definition = registry.GetResource(grant.Resource);

            // Stored with the registry's names, whatever casing the caller used.
            var permission = new ResourcePermission(RoleId, definition.Name);

            if (grant.Actions != ResourceActions.None)
                permission.Allow(grant.Actions);

            foreach (var (field, actions) in grant.FieldGrants)
            {
                var fieldName = definition.GetFieldName(field);

                if (actions == FieldsActions.None)
                    permission.CreateField(fieldName);
                else
                    permission.CreateField(fieldName, actions);
            }

            _resourcePermissions.Add(permission);
        }

        return result;
    }
}
