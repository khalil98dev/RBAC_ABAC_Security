using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecurityBuilder.Abstractions;
using SecurityBuilder.Common;

namespace SecurityBuilder.EntityFrameworkCore;

public static class RolePermissionStoreServiceCollectionExtensions
{
    /// <summary>
    /// Registers the EF Core <see cref="IRolePermissionStore"/> over the given DbContext, behind the
    /// role cache. The store is scoped, because the DbContext is; the cache is a singleton, so one
    /// role is read once for every request that presents it.
    ///
    /// Pass <see cref="TimeSpan.Zero"/> to read the permissions on every request instead of caching
    /// them. Otherwise an admin who edits a role should call <c>IRolePermissionCache.Invalidate</c>,
    /// which is why the cache is also registered under that interface.
    /// </summary>
    public static IServiceCollection AddRolePermissionStore<TContext>(
        this IServiceCollection services,
        TimeSpan? cacheDuration = null)
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(services);

        var duration = cacheDuration ?? RolePermissionCache.DefaultDuration;

        if (duration <= TimeSpan.Zero)
        {
            services.AddScoped<IRolePermissionStore, RolePermissionStore<TContext>>();
            return services;
        }

        var cache = new RolePermissionCache(duration);

        services.AddSingleton(cache);
        services.AddSingleton<IRolePermissionCache>(cache);
        services.AddScoped<IRolePermissionStore>(provider => new CachedRolePermissionStore(
            new RolePermissionStore<TContext>(provider.GetRequiredService<TContext>()),
            cache));

        return services;
    }
}
