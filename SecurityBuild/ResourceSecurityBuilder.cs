using System.Linq.Expressions;
using System.Reflection;
using TestPermissions.SecurityBuild.Actions;

public sealed class ResourceSecurityBuilder<T> where T : IAggregateRoot
{
    private readonly SecurityRegistry _registry;

    internal ResourceSecurityBuilder(SecurityRegistry registry)
    {
        _registry = registry;
    }

    public ResourceSecurityBuilder<T> HasName(string name)
    {
        _registry.SetName(typeof(T), name);
        return this;
    }

    public ResourceSecurityBuilder<T> SecureResource(params ResourceActions[] actions)
    {
        ArgumentNullException.ThrowIfNull(actions);

        _registry.AddResource(typeof(T), actions);

        return this;
    }

    public ResourceSecurityBuilder<T> SecureField<TValue>(Expression<Func<T, TValue>> selector, params FieldsActions[] actions)
    {
        ArgumentNullException.ThrowIfNull(selector);

        Expression body = selector.Body;

        if (body is UnaryExpression unary)
            body = unary.Operand;

        if (body is not MemberExpression member ||
            member.Member is not PropertyInfo property ||
            property.DeclaringType != typeof(T))
        {
            throw new ArgumentException(
                "Select a property directly on the resource.",
                nameof(selector));
        }

        _registry.AddField(typeof(T), property.Name, actions);

        return this;
    }
}
