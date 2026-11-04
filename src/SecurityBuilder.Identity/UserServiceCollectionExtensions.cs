using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SecurityBuilder.Abstractions;

namespace SecurityBuilder.Identity;

public static class UserServiceCollectionExtensions
{
    /// <summary>
    /// Registers the users package over the given DbContext: <see cref="UserAccountService{TContext}"/>,
    /// the password hasher, and the <see cref="ITokenSubjectProvider"/> the token service reads users
    /// through. Needs <c>AddJwtTokens</c> as well; a project with its own users skips this and
    /// registers its own subject provider instead.
    /// </summary>
    public static IServiceCollection AddUsers<TContext>(this IServiceCollection services)
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions();

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddScoped<IPasswordHasher<User>, PasswordHasher<User>>();
        services.TryAddScoped<ITokenSubjectProvider, UserTokenSubjectProvider<TContext>>();
        services.TryAddScoped<UserAccountService<TContext>>();

        return services;
    }
}
