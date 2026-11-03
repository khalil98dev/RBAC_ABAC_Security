using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Query;
using Microsoft.Extensions.DependencyInjection;

namespace SecurityBuilder.EntityFrameworkCore;

public static class SecurityDbContextOptionsExtensions
{
    /// <summary>
    /// Secures a DbContext for the <see cref="SecurityContext"/> of the current scope, resolved from
    /// the scope's service provider. This is the overload for
    /// <c>AddDbContext&lt;T&gt;((serviceProvider, options) =&gt; options.UseSecurity(serviceProvider))</c>.
    /// DbContext pooling is not supported: a pooled context would outlive the user it was built for.
    /// </summary>
    public static DbContextOptionsBuilder UseSecurity(
        this DbContextOptionsBuilder options,
        IServiceProvider serviceProvider)
    {
        ArgumentNullException.ThrowIfNull(serviceProvider);

        return options.UseSecurity(serviceProvider.GetRequiredService<SecurityContext>);
    }

    /// <summary>Secures a DbContext for one known SecurityContext, for tests and background jobs.</summary>
    public static DbContextOptionsBuilder UseSecurity(
        this DbContextOptionsBuilder options,
        SecurityContext security)
    {
        ArgumentNullException.ThrowIfNull(security);

        return options.UseSecurity(() => security);
    }

    public static DbContextOptionsBuilder<TContext> UseSecurity<TContext>(
        this DbContextOptionsBuilder<TContext> options,
        IServiceProvider serviceProvider) where TContext : DbContext
    {
        ((DbContextOptionsBuilder)options).UseSecurity(serviceProvider);
        return options;
    }

    public static DbContextOptionsBuilder<TContext> UseSecurity<TContext>(
        this DbContextOptionsBuilder<TContext> options,
        SecurityContext security) where TContext : DbContext
    {
        ((DbContextOptionsBuilder)options).UseSecurity(security);
        return options;
    }

    private static DbContextOptionsBuilder UseSecurity(
        this DbContextOptionsBuilder options,
        Func<SecurityContext> security)
    {
        ArgumentNullException.ThrowIfNull(options);

        ((IDbContextOptionsBuilderInfrastructure)options)
            .AddOrUpdateExtension(new SecurityOptionsExtension(security));

        return options
            // The read interceptor rewrites a query once and EF caches it, so the cache key has
            // to carry the visibility it was rewritten for. These two belong together.
            .ReplaceService<ICompiledQueryCacheKeyGenerator, SecurityCompiledQueryCacheKeyGenerator>()
            .AddInterceptors(SecuritySaveChangesInterceptor.Instance, SecurityQueryInterceptor.Instance);
    }
}
