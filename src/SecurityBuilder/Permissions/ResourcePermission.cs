using SecurityBuilder.Actions;
using SecurityBuilder.Permissions;

namespace SecurityBuilder.Permissions;

public sealed class ResourcePermission
{
    private readonly List<FieldPermission> _fieldPermissions = [];
    public Guid RoleId { get; private set; }
    public Guid ResourcePermissionId { get; private set; }
    public string Resource { get; private set; } = default!;
    public ResourceActions AllowedActions { get; private set; }

    public IReadOnlyCollection<FieldPermission> FieldPermissions =>
        _fieldPermissions.AsReadOnly();


    private ResourcePermission()
    {
        //for ef core
    }


    public ResourcePermission(Guid roleId, string resource)
    {
        if (roleId == Guid.Empty)
            throw new ArgumentException("Role ID cannot be empty.", nameof(roleId));

        ArgumentException.ThrowIfNullOrWhiteSpace(resource);
        ResourcePermissionId = Guid.CreateVersion7();
        RoleId = roleId;
        Resource = resource.Trim();
        AllowedActions = ResourceActions.None;
    }

    public void Allow(params ResourceActions[] actions)
    {
        ArgumentNullException.ThrowIfNull(actions);

        foreach (var action in actions)
        {
            if (action == ResourceActions.None ||
                (action & ~ResourceActions.All) != 0)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(actions), action, "Invalid resource action.");
            }

            AllowedActions |= action;
        }
    }

    public void Deny(params ResourceActions[] actions)
    {
        ArgumentNullException.ThrowIfNull(actions);

        foreach (var action in actions)
        {
            if (action == ResourceActions.None ||
                (action & ~ResourceActions.All) != 0)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(actions), action, "Invalid resource action.");
            }

            AllowedActions &= ~action;
        }
    }

    public bool Allows(ResourceActions action)
    {
        return action != ResourceActions.None &&
                (action & ~ResourceActions.All) == 0 &&
                (AllowedActions & action) == action;
    }


    public FieldPermission CreateField(string field, params FieldsActions[] allowedActions)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(field);

        if (_fieldPermissions.Any(x => string.Equals(x.Field, field.Trim(), StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException(
                $"Field permission for '{field}' already exists.");
        }

        var permission = new FieldPermission(ResourcePermissionId, field);

        _fieldPermissions.Add(permission);

        if (allowedActions is not null && allowedActions.Length > 0)
        {
            permission.Allow(allowedActions);
        }

        return permission;
    }

    public void AddFieldPermissions(IDictionary<string, FieldsActions> fields)
    {
        ArgumentNullException.ThrowIfNull(fields);

        foreach (var field in fields)
        {
            if (field.Value == FieldsActions.None)
                CreateField(field.Key);
            else
                CreateField(field.Key, field.Value);
        }
    }

    public bool RemoveFieldPermission(Guid resourceFieldId)
    {
        var permission = _fieldPermissions
            .SingleOrDefault(x => x.ResourceFieldId == resourceFieldId);

        return permission is not null &&
               _fieldPermissions.Remove(permission);
    }


    public bool HasPermission(Guid resourceFieldId, FieldsActions action)
    {
        return _fieldPermissions.Any(p => p.ResourceFieldId == resourceFieldId && p.Allows(action));
    }
}
