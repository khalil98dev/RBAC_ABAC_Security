using SecurityBuilder.Abstractions;
using SecurityBuilder.Actions;
using SecurityBuilder.Grants;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Runtime.ExceptionServices;

namespace SecurityBuilder;

public sealed class SecurityRegistry
{
    private readonly Dictionary<Type, ResourceDefinition> _resources = [];
    private bool _frozen;

    public IReadOnlyCollection<ResourceDefinition> Resources => _resources.Values;

    /// <summary>True once the catalog is closed. A frozen registry is safe to read from any thread.</summary>
    public bool IsFrozen => _frozen;

    /// <summary>
    /// Closes the catalog. Nothing can be configured afterwards, which is what makes a single
    /// registry safe to share: it is written during startup and only read after that.
    /// </summary>
    public SecurityRegistry Freeze()
    {
        _frozen = true;
        return this;
    }

    public SecurityRegistry Configure<T>(Action<ResourceSecurityBuilder<T>> configure) where T : IAggregateRoot
    {
        ArgumentNullException.ThrowIfNull(configure);
        EnsureNotFrozen();

        // Any configured resource is registered, even if it only secures fields.
        var definition = GetOrRegister(typeof(T));

        configure(new ResourceSecurityBuilder<T>(this));

        EnsureUniqueName(definition);

        return this;
    }

    public SecurityRegistry AddConfiguration<T>(IResourceSecurityConfiguration<T> configuration) where T : IAggregateRoot
    {
        ArgumentNullException.ThrowIfNull(configuration);

        return Configure<T>(configuration.Configure);
    }
    public SecurityRegistry AddFromAssembly(Assembly assembly)
    {
        ArgumentNullException.ThrowIfNull(assembly);

        var configurations = assembly.GetTypes()
            .Where(type =>
                type is { IsClass: true, IsAbstract: false } &&
                !type.IsGenericTypeDefinition)
            .SelectMany(type => type.GetInterfaces()
                .Where(i =>
                    i.IsGenericType &&
                    i.GetGenericTypeDefinition() == typeof(IResourceSecurityConfiguration<>))
                .Select(i => new { Type = type, Interface = i }));

        var addConfiguration = typeof(SecurityRegistry).GetMethod(nameof(AddConfiguration))!;

        foreach (var item in configurations)
        {
            var configuration = Activator.CreateInstance(item.Type)
                ?? throw new InvalidOperationException($"Could not create {item.Type.FullName}.");

            try
            {
                addConfiguration
                    .MakeGenericMethod(item.Interface.GetGenericArguments())
                    .Invoke(this, [configuration]);
            }
            catch (TargetInvocationException ex) when (ex.InnerException is not null)
            {
                ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
            }
        }

        return this;
    }

    internal void SetName(Type resourceType, string name)
    {
        EnsureNotFrozen();
        ArgumentNullException.ThrowIfNull(resourceType);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        var definition = GetOrRegister(resourceType);
        definition.Name = name.Trim();
        EnsureUniqueName(definition);
    }

    internal void AddResource(Type resourceType, IEnumerable<ResourceActions> actions)
    {
        EnsureNotFrozen();
        ArgumentNullException.ThrowIfNull(resourceType);
        ArgumentNullException.ThrowIfNull(actions);

        var configured = actions.ToArray();

        // R2: no actions => every action is secured; explicit actions => only those.
        GetOrRegister(resourceType).AddActions(configured.Length == 0 ? ResourceActions.All : Combine(configured));
    }




    internal void AddField(Type resourceType, string propertyName, IEnumerable<FieldsActions> actions)
    {
        EnsureNotFrozen();
        ArgumentNullException.ThrowIfNull(resourceType);
        ArgumentException.ThrowIfNullOrWhiteSpace(propertyName);
        ArgumentNullException.ThrowIfNull(actions);

        GetOrRegister(resourceType).AddField(propertyName, Combine(actions));
    }



    public bool TryGetResource(Type resourceType, [NotNullWhen(true)] out ResourceDefinition? definition)
    {
        ArgumentNullException.ThrowIfNull(resourceType);
        return _resources.TryGetValue(resourceType, out definition);
    }

    public bool TryGetResource(string name, [NotNullWhen(true)] out ResourceDefinition? definition)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        definition = _resources.Values.FirstOrDefault(r =>
            string.Equals(r.Name, name.Trim(), StringComparison.OrdinalIgnoreCase));

        return definition is not null;
    }

    public ResourceDefinition GetResource(Type resourceType)
    {
        return TryGetResource(resourceType, out var definition)
            ? definition
            : throw new InvalidOperationException($"The resource type '{resourceType.FullName}' is not secured.");
    }

    public ResourceDefinition GetResource(string name)
    {
        return TryGetResource(name, out var definition)
            ? definition
            : throw new InvalidOperationException($"The resource '{name}' is not secured.");
    }

    public ResourceActions GetResourceActions(Type resourceType) => GetResource(resourceType).Actions;

    public IReadOnlyDictionary<string, FieldsActions> GetSecuredFields(Type resourceType)
    {
        return TryGetResource(resourceType, out var definition)
            ? definition.Fields
            : new Dictionary<string, FieldsActions>();
    }

    public bool IsResourceHasActions(Type resourceType, params ResourceActions[] actions)
    {
        if (!TryGetResource(resourceType, out var definition))
            return false;

        var required = Combine(actions);
        return (definition.Actions & required) == required;
    }

    public bool IsFieldHasActions(Type resourceType, string field, params FieldsActions[] actions)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(field);




        if (!TryGetResource(resourceType, out var definition) ||
            !definition.Fields.TryGetValue(field, out var fieldActions))
        {
            return false;
        }

        var required = Combine(actions);
        return (fieldActions & required) == required;
    }

    public SecurityValidationResult ValidateGrant(PermissionGrant grant) => ValidateGrants([grant]);

    /// <summary>Checks grants against the registry and returns every error found.</summary>
    public SecurityValidationResult ValidateGrants(IEnumerable<PermissionGrant> grants)
    {
        ArgumentNullException.ThrowIfNull(grants);

        var result = new SecurityValidationResult();
        var seenResources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var grant in grants)
        {
            if (grant is null || string.IsNullOrWhiteSpace(grant.Resource))
            {
                result.Add(new SecurityError("resource.required", "Each grant needs a resource name."));
                continue;
            }

            if (!seenResources.Add(grant.Resource.Trim()))
            {
                result.Add(new SecurityError("resource.duplicate",
                    $"Resource '{grant.Resource}' is granted more than once.", grant.Resource));
                continue;
            }

            if (!TryGetResource(grant.Resource, out var resource))
            {
                result.Add(new SecurityError("resource.unknown",
                    $"Resource '{grant.Resource}' is not secured.", grant.Resource));
                continue;
            }

            ValidateResourceActions(resource, grant.Actions, result);
            ValidateFields(resource, grant.FieldGrants, result);
        }

        return result;
    }

    private static void ValidateResourceActions(
        ResourceDefinition resource,
        ResourceActions requested,
        SecurityValidationResult result)
    {
        var notSecured = requested & ~resource.Actions;

        if (notSecured != ResourceActions.None)
        {
            result.Add(new SecurityError("resource.action_not_secured",
                $"'{resource.Name}' does not secure: {notSecured}.", resource.Name));
        }
    }

    private static void ValidateFields(
        ResourceDefinition resource,
        IReadOnlyDictionary<string, FieldsActions> fields,
        SecurityValidationResult result)
    {
        var seenFields = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (field, requested) in fields)
        {
            var name = field.Trim();

            if (!seenFields.Add(name))
            {
                result.Add(new SecurityError("field.duplicate",
                    $"Field '{name}' is granted more than once on '{resource.Name}'.", resource.Name, name));
                continue;
            }

            if (!resource.Fields.TryGetValue(name, out var securedActions))
            {
                result.Add(new SecurityError("field.unknown",
                    $"Field '{name}' is not secured on '{resource.Name}'.", resource.Name, name));
                continue;
            }

            var notSecured = requested & ~securedActions;

            if (notSecured != FieldsActions.None)
            {
                result.Add(new SecurityError("field.action_not_secured",
                    $"'{resource.Name}.{resource.GetFieldName(name)}' does not secure: {notSecured}.", resource.Name, name));
            }
        }
    }

    internal static void EnsureSingleAction(ResourceActions action)
    {
        var value = (int)action;

        if (value == 0 || (action & ~ResourceActions.All) != 0 || (value & (value - 1)) != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(action), action,
                "Specify exactly one resource action (Create, Delete, Read or Set).");
        }
    }

    private void EnsureNotFrozen()
    {
        if (_frozen)
        {
            throw new InvalidOperationException(
                "The security registry is frozen. Configure every resource during startup.");
        }
    }

    private ResourceDefinition GetOrRegister(Type resourceType)
    {
        if (!typeof(IAggregateRoot).IsAssignableFrom(resourceType))
            throw new ArgumentException($"'{resourceType.FullName}' is not an aggregate root.", nameof(resourceType));

        if (!_resources.TryGetValue(resourceType, out var definition))
        {
            definition = new ResourceDefinition(resourceType);
            _resources.Add(resourceType, definition);
        }

        return definition;
    }

    private void EnsureUniqueName(ResourceDefinition definition)
    {
        var clash = _resources.Values.FirstOrDefault(r =>
            r != definition &&
            string.Equals(r.Name, definition.Name, StringComparison.OrdinalIgnoreCase));

        if (clash is not null)
        {
            throw new InvalidOperationException(
                $"Resource name '{definition.Name}' is used by both '{clash.ResourceType.FullName}' and " +
                $"'{definition.ResourceType.FullName}'. Use HasName(...) to give one of them a unique name.");
        }
    }
    private static ResourceActions Combine(IEnumerable<ResourceActions> actions)
    {
        ArgumentNullException.ThrowIfNull(actions);

        var result = ResourceActions.None;
        var any = false;

        foreach (var action in actions)
        {
            if (action == ResourceActions.None || (action & ~ResourceActions.All) != 0)
                throw new ArgumentOutOfRangeException(nameof(actions), action, "The resource action contains invalid flags.");

            result |= action;
            any = true;
        }

        if (!any)
            throw new ArgumentException("At least one resource action must be specified.", nameof(actions));

        return result;
    }
    private static FieldsActions Combine(IEnumerable<FieldsActions> actions)
    {
        ArgumentNullException.ThrowIfNull(actions);

        var result = FieldsActions.None;
        var any = false;

        foreach (var action in actions)
        {
            if (action == FieldsActions.None || (action & ~FieldsActions.All) != 0)
                throw new ArgumentOutOfRangeException(nameof(actions), action, "The field action contains invalid flags.");

            result |= action;
            any = true;
        }

        if (!any)
            throw new ArgumentException("At least one field action must be specified.", nameof(actions));

        return result;
    }
}
