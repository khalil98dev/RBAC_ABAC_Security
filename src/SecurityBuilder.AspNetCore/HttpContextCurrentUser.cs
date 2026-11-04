using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using SecurityBuilder.Abstractions;

namespace SecurityBuilder.AspNetCore;

/// <summary>
/// The caller of the current HTTP request, read from its <c>ClaimsPrincipal</c>.
///
/// Outside a request there is no HttpContext - a hosted service, a seeding routine - and then this
/// reports the anonymous user instead of throwing. Code that needs an author there should use
/// <see cref="StaticCurrentUser.System"/>.
/// </summary>
public sealed class HttpContextCurrentUser(
    IHttpContextAccessor accessor,
    IOptions<SecurityBuilderOptions> options) : ICurrentUser
{
    private ICurrentUser Current => _current ??= Read();
    private ICurrentUser? _current;

    public string? UserId => Current.UserId;

    public string? UserName => Current.UserName;

    public string? Email => Current.Email;

    public bool IsAuthenticated => Current.IsAuthenticated;

    public IReadOnlyCollection<string> Roles => Current.Roles;

    private ICurrentUser Read()
    {
        var principal = accessor.HttpContext?.User;

        if (principal?.Identity?.IsAuthenticated != true)
            return StaticCurrentUser.Anonymous;

        var settings = options.Value;

        return new StaticCurrentUser(
            principal.FindFirst(settings.UserIdClaimType)?.Value,
            principal.FindFirst(settings.UserNameClaimType)?.Value,
            principal.FindFirst(settings.EmailClaimType)?.Value,
            isAuthenticated: true,
            RoleClaims.Read(principal, settings.RoleClaimType));
    }
}
