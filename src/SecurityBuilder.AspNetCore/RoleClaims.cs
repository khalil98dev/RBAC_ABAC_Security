using System.Security.Claims;

namespace SecurityBuilder.AspNetCore;

/// <summary>The one place that decides how role names are pulled out of a principal.</summary>
internal static class RoleClaims
{
    public static string[] Read(ClaimsPrincipal principal, string roleClaimType) =>
        principal
            .FindAll(claim => string.Equals(claim.Type, roleClaimType, StringComparison.OrdinalIgnoreCase))
            .Select(claim => claim.Value)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
}
