using System.Reflection;
using Microsoft.Extensions.DependencyInjection;

namespace SecurityBuilder.AspNetCore;

public static class SecurityBuilderServiceCollectionExtensions
{
    /// <summary>
    /// Builds the catalog once from the <c>IResourceSecurityConfiguration&lt;T&gt;</c> classes in the
    /// given assemblies, freezes it, and registers it as a singleton. The current user's
    /// <see cref="SecurityContext"/> is scoped: one per request, anonymous until something signs it in.
    ///
    /// Also maps <see cref="AccessDeniedException"/> to a 403 ProblemDetails response. That only takes
    /// effect once the app calls <c>UseExceptionHandler</c>.
    /// </summary>
    public static IServiceCollection AddSecurityBuilder(
        this IServiceCollection services,
        params Assembly[] configurationAssemblies)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configurationAssemblies);

        if (configurationAssemblies.Length == 0)
        {
            throw new ArgumentException(
                "Name at least one assembly holding IResourceSecurityConfiguration<T> classes.",
                nameof(configurationAssemblies));
        }

        var registry = new SecurityRegistry();

        foreach (var assembly in configurationAssemblies)
            registry.AddFromAssembly(assembly);

        // Written at startup, only read afterwards: that is what makes one instance safe to share.
        registry.Freeze();

        services.AddSingleton(registry);
        services.AddScoped<SecurityContext>();
        services.AddExceptionHandler<AccessDeniedExceptionHandler>();

        return services;
    }
}
