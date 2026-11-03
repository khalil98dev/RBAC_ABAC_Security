using System.Security.Claims;

namespace SecurityBuilder.AspNetCore;

/// <summary>
/// How SecurityBuilder reads the signed-in user: claim types only. The library never issues or
/// validates the token itself, which is what keeps it authentication-agnostic. Moving to another
/// identity provider later is a change here, not in the library.
/// </summary>
public sealed class SecurityBuilderOptions
{
    /// <summary>The claim holding a role name. Keycloak and some JWT issuers use a different type.</summary>
    public string RoleClaimType { get; set; } = ClaimTypes.Role;

    public string UserIdClaimType { get; set; } = ClaimTypes.NameIdentifier;

    public string UserNameClaimType { get; set; } = ClaimTypes.Name;

    public string EmailClaimType { get; set; } = ClaimTypes.Email;
}
