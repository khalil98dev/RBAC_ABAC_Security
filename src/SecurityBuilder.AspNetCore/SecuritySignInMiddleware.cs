using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SecurityBuilder.Abstractions;

namespace SecurityBuilder.AspNetCore;

/// <summary>
/// Signs the request's <see cref="SecurityContext"/> in from the authenticated principal: it reads the
/// role claims, loads those roles' permissions and hands them over. Nothing here knows about JWT,
/// cookies or any provider - only claims.
///
/// An unauthenticated request is left anonymous, which under R1 means every secured resource is denied.
/// </summary>
public sealed class SecuritySignInMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(
        HttpContext context,
        SecurityContext security,
        IOptions<SecurityBuilderOptions> options)
    {
        ArgumentNullException.ThrowIfNull(context);

        var roleNames = context.User?.Identity?.IsAuthenticated == true
            ? RoleClaims.Read(context.User, options.Value.RoleClaimType)
            : [];

        if (roleNames.Length > 0)
        {
            var store = context.RequestServices.GetService<IRolePermissionStore>()
                ?? throw new InvalidOperationException(
                    "No IRolePermissionStore is registered, so role claims cannot be turned into " +
                    "permissions. Call AddRolePermissionStore<TContext>() or register your own.");

            security.SignIn(await store.GetRolesAsync(roleNames, context.RequestAborted));
        }

        await next(context);
    }
}

public static class SecurityBuilderApplicationBuilderExtensions
{
    /// <summary>
    /// Signs the current user in for the rest of the pipeline. Place it after
    /// <c>UseAuthentication</c>, which is what puts the principal on the context.
    /// </summary>
    public static IApplicationBuilder UseSecurityBuilder(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        return app.UseMiddleware<SecuritySignInMiddleware>();
    }
}
