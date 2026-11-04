using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SecurityBuilder.Abstractions;

namespace SecurityBuilder.Identity;

public static class JwtTokenServiceCollectionExtensions
{
    /// <summary>
    /// Registers the JWT <see cref="ISecurityTokenService"/> and the refresh token store over the
    /// given DbContext, which must map the table with <c>ApplyIdentityModel</c>.
    ///
    /// Everything goes in with <c>TryAdd</c>, so registering your own implementation of any of these
    /// first keeps it. The one thing this does not register is <see cref="ITokenSubjectProvider"/>:
    /// only the application knows where its users are.
    ///
    /// This registers no authentication: the host still adds JwtBearer, with the same issuer,
    /// audience and signing key it configures here.
    /// </summary>
    public static IServiceCollection AddJwtTokens<TContext>(
        this IServiceCollection services,
        Action<JwtOptions> configure)
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddScoped<IRefreshTokenStore, EfRefreshTokenStore<TContext>>();
        services.TryAddScoped<ISecurityTokenService, JwtSecurityTokenService>();

        return services;
    }
}
