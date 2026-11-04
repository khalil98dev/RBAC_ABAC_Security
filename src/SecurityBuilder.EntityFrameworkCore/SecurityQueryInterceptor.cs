using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore.Diagnostics;
using SecurityBuilder.Actions;

namespace SecurityBuilder.EntityFrameworkCore;

/// <summary>
/// Applies the read pipeline to every query before it is compiled:
///   step 1, the resource: Read denied => AccessDeniedException, nothing is cached;
///   step 2, the fields:   hidden fields become null in projections (see FieldMaskRewriter).
///
/// EF compiles a query once and reuses it, so this runs once per query shape per visibility.
/// It is safe only together with SecurityCompiledQueryCacheKeyGenerator, which puts the
/// current user's visibility into the cache key. Without it a cached query would be handed
/// to the next user unchanged.
///
/// Stateless on purpose: one instance serves every user, so EF keeps one service provider.
/// </summary>
public sealed class SecurityQueryInterceptor : IQueryExpressionInterceptor
{
    public static readonly SecurityQueryInterceptor Instance = new();

    private SecurityQueryInterceptor()
    {
    }

    public Expression QueryCompilationStarting(Expression queryExpression, QueryExpressionEventData eventData)
    {
        var security = eventData.Context?.GetSecurity();

        if (security is null || security.IsSystem)
            return queryExpression;

        var registry = security.Registry;

        DenyUnreadableResources(queryExpression, registry, security);

        return FieldMaskRewriter.Rewrite(queryExpression, registry, security.Access);
    }

    /// <summary>Step 1: a resource whose Read is secured and not granted stops the whole request.</summary>
    private static void DenyUnreadableResources(Expression query, SecurityRegistry registry, SecurityContext security)
    {
        foreach (var resourceType in new ResourceCollector(registry).Collect(query))
        {
            var result = security.Access.Authorize(resourceType, ResourceActions.Read);

            if (!result.IsAllowed)
                throw new AccessDeniedException(result.Reason ?? "Access denied.", []);
        }
    }

    /// <summary>The secured resources a query reads from.</summary>
    private sealed class ResourceCollector(SecurityRegistry registry) : ExpressionVisitor
    {
        private readonly HashSet<Type> _resources = [];

        public IReadOnlyCollection<Type> Collect(Expression query)
        {
            Visit(query);
            return _resources;
        }

        public override Expression? Visit(Expression? node)
        {
            if (ElementType(node?.Type) is { } element && registry.TryGetResource(element, out _))
                _resources.Add(element);

            return base.Visit(node);
        }

        private static Type? ElementType(Type? type) =>
            type is { IsGenericType: true } && typeof(IQueryable).IsAssignableFrom(type)
                ? type.GetGenericArguments().SingleOrDefault()
                : null;
    }
}
