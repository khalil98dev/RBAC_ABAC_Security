using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Query;

namespace SecurityBuilder.EntityFrameworkCore;

/// <summary>
/// Adds the current user's visibility to EF's compiled-query cache key.
///
/// This is what makes the read side safe. SecurityQueryInterceptor rewrites a query once and
/// EF caches the result, so without this a query compiled for one user would be reused for the
/// next one, masked fields and all. With it, a cached query is only ever reused by a user who
/// reads exactly the same fields.
///
/// It runs on every execution, not only on a cache miss, so the signature it reads is computed
/// once per AccessEvaluator and then just handed back.
/// </summary>
public sealed class SecurityCompiledQueryCacheKeyGenerator(
    CompiledQueryCacheKeyGeneratorDependencies dependencies,
    RelationalCompiledQueryCacheKeyGeneratorDependencies relationalDependencies)
    : RelationalCompiledQueryCacheKeyGenerator(dependencies, relationalDependencies)
{
    private readonly ICurrentDbContext _currentContext = dependencies.CurrentContext;

    public override object GenerateCacheKey(Expression query, bool async) =>
        new SecurityCacheKey(base.GenerateCacheKey(query, async), Visibility());

    private string Visibility() =>
        _currentContext.Context.GetSecurity()?.ReadVisibility ?? "unsecured";

    private sealed record SecurityCacheKey(object Query, string Visibility);
}
