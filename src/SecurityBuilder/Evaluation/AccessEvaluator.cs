using SecurityBuilder.Abstractions;
using SecurityBuilder.Actions;
using SecurityBuilder.Common;
using SecurityBuilder.Permissions;

namespace SecurityBuilder.Evaluation;

/// <summary>
/// Decides what one user (all their roles together) can do on a resource.
///
///  1. Resource: if the action is secured and no role grants it, the request is denied.
///  2. Fields:   secured fields the user is not granted are returned in DeniedFields.
///               Read => the request stays allowed, return those fields as null.
///               Set  => the whole request is denied.
///
/// Anything not configured in the registry is open.
/// </summary>
public sealed class AccessEvaluator
{
    private readonly SecurityRegistry _registry;
    private readonly Dictionary<string, UserAccess> _accessByResource = new(StringComparer.OrdinalIgnoreCase);
    private string? _readVisibility;

    public AccessEvaluator(SecurityRegistry registry, IEnumerable<Role> roles)
    {
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(roles);

        _registry = registry;

        foreach (var permission in roles.SelectMany(role => role.ResourcePermissions))
            Merge(permission);
    }

    /// <summary>
    /// Everything this user may read, as one short string. Two users with the same text see exactly
    /// the same fields, so they can safely share anything cached per visibility (a compiled query).
    /// Computed once: the permissions of an evaluator never change.
    /// </summary>
    public string ReadVisibility => _readVisibility ??= DescribeReadVisibility();

    private string DescribeReadVisibility()
    {
        var resources = _registry.Resources
            .OrderBy(resource => resource.Name, StringComparer.Ordinal)
            .Select(resource =>
            {
                var access = Authorize(resource.ResourceType, ResourceActions.Read, FieldsActions.Read);

                return $"{resource.Name}:{(access.IsAllowed ? "read" : "denied")}:{string.Join(",", access.DeniedFields.Order())}";
            });

        return string.Join("|", resources);
    }

    public AccessResult Authorize<T>(
        ResourceActions action,
        FieldsActions fieldAction = FieldsActions.None,
        params string[] fields) where T : IAggregateRoot
    {
        return Authorize(typeof(T), action, fieldAction, fields.Length == 0 ? null : fields);
    }

    /// <param name="resourceType">The aggregate type, as registered.</param>
    /// <param name="action">One resource action (Create, Read, Set or Delete).</param>
    /// <param name="fieldAction">Read or Set to check fields, None to skip them.</param>
    /// <param name="fields">Fields to check. Null = every secured field of the resource.</param>
    public AccessResult Authorize(
        Type resourceType,
        ResourceActions action,
        FieldsActions fieldAction = FieldsActions.None,
        IEnumerable<string>? fields = null)
    {
        ArgumentNullException.ThrowIfNull(resourceType);
        SecurityRegistry.EnsureSingleAction(action);

        if (fieldAction is not (FieldsActions.None or FieldsActions.Read or FieldsActions.Set))
            throw new ArgumentOutOfRangeException(nameof(fieldAction), fieldAction, "Use None, Read or Set.");

        if (!_registry.TryGetResource(resourceType, out var resource))
            return AccessResult.Allow();

        var access = _accessByResource.GetValueOrDefault(resource.Name) ?? new UserAccess();

        if (!HasResourceAccess(resource, access, action))
            return AccessResult.Deny($"Missing '{action}' permission on '{resource.Name}'.");

        var deniedFields = FindDeniedFields(resource, access, fieldAction, fields);

        if (fieldAction == FieldsActions.Set && deniedFields.Count > 0)
            return AccessResult.Deny($"Not allowed to set: {string.Join(", ", deniedFields)}.", deniedFields);

        return AccessResult.Allow(deniedFields);
    }

    private static bool HasResourceAccess(ResourceDefinition resource, UserAccess access, ResourceActions action)
    {
        var isSecured = resource.Actions.HasFlag(action);

        return !isSecured || access.Actions.HasFlag(action);
    }

    private static List<string> FindDeniedFields(
        ResourceDefinition resource,
        UserAccess access,
        FieldsActions fieldAction,
        IEnumerable<string>? fields)
    {
        if (fieldAction == FieldsActions.None)
            return [];

        var deniedFields = new List<string>();

        foreach (var field in (fields ?? resource.Fields.Keys).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var isSecured = resource.Fields.TryGetValue(field, out var securedActions) &&
                            securedActions.HasFlag(fieldAction);

            if (isSecured && !access.HasField(field, fieldAction))
                deniedFields.Add(resource.GetFieldName(field));
        }

        return deniedFields;
    }

    private void Merge(ResourcePermission permission)
    {
        if (!_accessByResource.TryGetValue(permission.Resource, out var access))
        {
            access = new UserAccess();
            _accessByResource[permission.Resource] = access;
        }

        access.Actions |= permission.AllowedActions;

        foreach (var field in permission.FieldPermissions)
        {
            access.Fields.TryGetValue(field.Field, out var current);
            access.Fields[field.Field] = current | field.AllowedActions;
        }
    }

    /// <summary>What the user's roles grant on one resource, combined.</summary>
    private sealed class UserAccess
    {
        public ResourceActions Actions { get; set; }

        public Dictionary<string, FieldsActions> Fields { get; } = new(StringComparer.OrdinalIgnoreCase);

        public bool HasField(string field, FieldsActions action) =>
            Fields.TryGetValue(field, out var granted) && granted.HasFlag(action);
    }
}
