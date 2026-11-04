using SecurityBuilder.Actions;

namespace SecurityBuilder.Grants;

/// <summary>
/// What a caller (admin UI, API...) asks to grant a role on one resource.
/// Names are the registry names (resource) and property names (fields), case-insensitive.
/// </summary>
public sealed record PermissionGrant(string Resource,ResourceActions Actions,IReadOnlyDictionary<string, FieldsActions>? Fields = null)
{
    private static readonly IReadOnlyDictionary<string, FieldsActions> NoFields =
        new Dictionary<string, FieldsActions>();

    public IReadOnlyDictionary<string, FieldsActions> FieldGrants => Fields ?? NoFields;
}
