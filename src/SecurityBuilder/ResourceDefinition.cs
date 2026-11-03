using SecurityBuilder.Actions;

namespace SecurityBuilder;

public sealed class ResourceDefinition
{
    private readonly Dictionary<string, FieldsActions> _fields = new(StringComparer.OrdinalIgnoreCase);

    internal ResourceDefinition(Type resourceType)
    {
        ResourceType = resourceType;
        Name = resourceType.Name;
        Actions = ResourceActions.None;
    }

    public Type ResourceType { get; }

    public string Name { get; internal set; }

    public ResourceActions Actions { get; private set; }

    public IReadOnlyDictionary<string, FieldsActions> Fields => _fields;

    internal void AddActions(ResourceActions actions) => Actions |= actions;

    internal string GetFieldName(string field)
    {
        var trimmed = field.Trim();
        return _fields.Keys.FirstOrDefault(k => string.Equals(k, trimmed, StringComparison.OrdinalIgnoreCase)) ?? trimmed;
    }

    internal void AddField(string field, FieldsActions actions)
    {
        _fields[field] = _fields.TryGetValue(field, out var existing)
            ? existing | actions
            : actions;
    }
}
