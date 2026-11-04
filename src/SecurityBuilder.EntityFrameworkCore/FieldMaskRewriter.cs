using System.Linq.Expressions;
using SecurityBuilder.Actions;
using SecurityBuilder.Evaluation;

namespace SecurityBuilder.EntityFrameworkCore;

/// <summary>
/// Rewrites one query for one visibility:
///   inside a Select projection a field the user may not read becomes null ;
///   anywhere else - Where, OrderBy, aggregates - using such a field is denied.
/// Fields the registry does not secure for Read are left untouched, so entity queries
/// (which read no field in the query itself) come back whole.
/// </summary>
internal sealed class FieldMaskRewriter(SecurityRegistry registry, AccessEvaluator access) : ExpressionVisitor
{
    private readonly Dictionary<Type, IReadOnlyList<string>> _hiddenFields = [];
    private bool _inProjection;

    public static Expression Rewrite(Expression query, SecurityRegistry registry, AccessEvaluator access) =>
        new FieldMaskRewriter(registry, access).Visit(query);

    protected override Expression VisitMethodCall(MethodCallExpression node)
    {
        if (!IsSelect(node))
            return base.VisitMethodCall(node);

        // The source keeps the current mode; only the projection itself may mask.
        var source = Visit(node.Arguments[0]);
        var projections = node.Arguments.Skip(1).Select(VisitProjection);

        return node.Update(node.Object, [source, .. projections]);
    }

    protected override Expression VisitUnary(UnaryExpression node)
    {
        // new OrderDto(..., (decimal?)o.TotalAmmount, ...): hide the conversion, so the mask is null.
        if (node.NodeType == ExpressionType.Convert &&
            Nullable.GetUnderlyingType(node.Type) is not null &&
            node.Operand is MemberExpression member &&
            IsHidden(member, out var resource))
        {
            return Hide(resource, member, node.Type);
        }

        return base.VisitUnary(node);
    }

    protected override Expression VisitMember(MemberExpression node) =>
        IsHidden(node, out var resource)
            ? Hide(resource, node, node.Type)
            : base.VisitMember(node);

    /// <summary>
    /// A hidden field is replaced by a constant null, so the column is never even selected.
    /// This is a constant on purpose: the compiled query is cached per visibility, never per user.
    /// </summary>
    private Expression Hide(ResourceDefinition resource, MemberExpression member, Type type)
    {
        var field = member.Member.Name;

        if (!_inProjection)
        {
            throw new AccessDeniedException(
                $"Not allowed to read '{resource.Name}.{field}', so it cannot be used to filter or sort.",
                [field]);
        }

        if (type.IsValueType && Nullable.GetUnderlyingType(type) is null)
        {
            throw new InvalidOperationException(
                $"'{resource.Name}.{field}' can be hidden from the current user, so it cannot be projected " +
                $"into '{type.Name}'. Project it into '{type.Name}?' instead.");
        }

        return Expression.Constant(null, type);
    }

    private Expression VisitProjection(Expression projection)
    {
        var outer = _inProjection;
        _inProjection = true;

        try
        {
            return Visit(projection);
        }
        finally
        {
            _inProjection = outer;
        }
    }

    private bool IsHidden(MemberExpression node, out ResourceDefinition resource)
    {
        resource = default!;

        return node.Expression is not null &&
               registry.TryGetResource(node.Expression.Type, out resource!) &&
               HiddenFields(resource).Contains(node.Member.Name, StringComparer.OrdinalIgnoreCase);
    }

    private IReadOnlyList<string> HiddenFields(ResourceDefinition resource)
    {
        if (_hiddenFields.TryGetValue(resource.ResourceType, out var hidden))
            return hidden;

        hidden = access
            .Authorize(resource.ResourceType, ResourceActions.Read, FieldsActions.Read)
            .DeniedFields;

        _hiddenFields[resource.ResourceType] = hidden;

        return hidden;
    }

    private static bool IsSelect(MethodCallExpression node) =>
        node.Method.Name == nameof(Queryable.Select) &&
        (node.Method.DeclaringType == typeof(Queryable) || node.Method.DeclaringType == typeof(Enumerable));
}
