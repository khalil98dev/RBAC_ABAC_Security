using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using SecurityBuilder.Abstractions;

namespace SecurityBuilder.AspNetCore;

public static class SecurityBuilderServiceCollectionExtensions
{
    /// <summary>
    /// Builds the catalog once from the <c>IResourceSecurityConfiguration&lt;T&gt;</c> classes in the
    /// given assemblies, freezes it, and registers it as a singleton. The current user's
    /// <see cref="SecurityContext"/> and <see cref="ICurrentUser"/> are scoped: one per request,
    /// anonymous until <c>UseSecurityBuilder</c> signs them in.
    ///
    /// Also maps <see cref="AccessDeniedException"/> to a 403 ProblemDetails response. That only takes
    /// effect once the app calls <c>UseExceptionHandler()</c> - which itself refuses to start unless the
    /// app also calls <c>AddProblemDetails()</c> or gives it an error path. Neither is done here, so
    /// adding SecurityBuilder does not change how the rest of the app renders errors.
    /// </summary>
    public static IServiceCollection AddSecurityBuilder(
        this IServiceCollection services,
        params Assembly[] configurationAssemblies) =>
        services.AddSecurityBuilder(configure: null, configurationAssemblies);

    /// <summary>
    /// The same, with the claim types the signed-in user is read from - the one place to change when
    /// the token comes from somewhere else.
    /// </summary>
    public static IServiceCollection AddSecurityBuilder(
        this IServiceCollection services,
        Action<SecurityBuilderOptions>? configure,
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

        services.AddOptions<SecurityBuilderOptions>();

        if (configure is not null)
            services.Configure(configure);

        services.AddHttpContextAccessor();
        services.AddScoped<ICurrentUser, HttpContextCurrentUser>();

        services.AddExceptionHandler<AccessDeniedExceptionHandler>();

        return services;
    }
}
