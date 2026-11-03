using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Query;

namespace SecurityBuilder.EntityFrameworkCore;

public static class SecurityDbContextOptionsExtensions
{
    /// <summary>
    /// Secures a DbContext: writes are checked when they are saved, reads are checked and masked
    /// when they are compiled. Use one SecurityContext per scope; DbContext pooling is not supported.
    /// </summary>
    public static DbContextOptionsBuilder UseSecurity(this DbContextOptionsBuilder options, SecurityContext security)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(security);

        ((IDbContextOptionsBuilderInfrastructure)options)
            .AddOrUpdateExtension(new SecurityOptionsExtension(security));

        return options
            // The read interceptor rewrites a query once and EF caches it, so the cache key has
            // to carry the visibility it was rewritten for. These two belong together.
            .ReplaceService<ICompiledQueryCacheKeyGenerator, SecurityCompiledQueryCacheKeyGenerator>()
            .AddInterceptors(SecuritySaveChangesInterceptor.Instance, SecurityQueryInterceptor.Instance);
    }

    public static DbContextOptionsBuilder<TContext> UseSecurity<TContext>(
        this DbContextOptionsBuilder<TContext> options,
        SecurityContext security) where TContext : DbContext
    {
        ((DbContextOptionsBuilder)options).UseSecurity(security);
        return options;
    }
}
