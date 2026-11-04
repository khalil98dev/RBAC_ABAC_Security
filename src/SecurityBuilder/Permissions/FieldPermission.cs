using SecurityBuilder.Actions;

namespace SecurityBuilder.Permissions;

public sealed class FieldPermission
{
    public Guid ResourcePermissionId { get; private set; }
    public Guid ResourceFieldId { get; private set; }
    public string Field { get; private set; }

    public FieldsActions AllowedActions { get; private set; }

    private FieldPermission()
    {
        //ef core
        Field = null!;
    }

    internal FieldPermission(Guid resourcePermissionId, string field)
    {
        if (resourcePermissionId == Guid.Empty)
            throw new ArgumentException(
                "Resource permission ID cannot be empty.",
                nameof(resourcePermissionId));

        ArgumentException.ThrowIfNullOrWhiteSpace(field);
        ResourceFieldId = Guid.CreateVersion7();
        ResourcePermissionId = resourcePermissionId;
        Field = field.Trim();
        AllowedActions = FieldsActions.None;
    }

    public void Allow(params FieldsActions[] actions)
    {
        ArgumentNullException.ThrowIfNull(actions);

        foreach (var action in actions)
        {
            if (action == FieldsActions.None ||
                (action & ~FieldsActions.All) != 0)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(actions), action, "Invalid field action.");
            }

            AllowedActions |= action;
        }
    }

    public void Deny(params FieldsActions[] actions)
    {
        ArgumentNullException.ThrowIfNull(actions);

        foreach (var action in actions)
        {
            if (action == FieldsActions.None ||
                (action & ~FieldsActions.All) != 0)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(actions), action, "Invalid field action.");
            }

            AllowedActions &= ~action;
        }
    }

    public bool Allows(FieldsActions action) => action != FieldsActions.None &&
                                                (action & ~FieldsActions.All) == 0 &&
                                                (AllowedActions & action) == action;
}