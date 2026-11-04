using Microsoft.EntityFrameworkCore;
using SecurityBuilder.Abstractions;
using SecurityBuilder.Actions;
using SecurityBuilder.Common;
using SecurityBuilder.Grants;
using SecurityBuilder.Identity;

namespace SecurityBuilder.Sample.Api.Endpoints;

/// <summary>The same shape as <see cref="PermissionGrant"/>, so what GET returns can be PUT back.</summary>
public sealed record GrantDto(string Resource, ResourceActions Actions, Dictionary<string, FieldsActions> Fields);

public sealed record RoleDto(string Name, string Description, IReadOnlyList<GrantDto> Grants);

public sealed record CreateUserRequest(string UserName, string? Email, string Password, string[] Roles);

public sealed record UserDto(Guid UserId, string UserName, string? Email, bool IsActive, IReadOnlyList<string> Roles);

/// <summary>
/// Managing roles and users. Guarded by ASP.NET Core's own role check: these are not secured
/// resources, they are the place where resources are secured.
/// </summary>
internal static class AdminEndpoints
{
    public static IEndpointRouteBuilder MapAdminEndpoints(this IEndpointRouteBuilder app)
    {
        var admin = app.MapGroup("/admin").RequireAuthorization(policy => policy.RequireRole("Admin"));

        admin.MapGet("/roles", async (SampleDbContext db, CancellationToken ct) =>
            (await db.Set<Role>().AsNoTracking().OrderBy(role => role.RoleName).ToListAsync(ct)).Select(ToDto));

        // R7: every error comes back at once, as 400, and the role is left as it was.
        admin.MapPut("/roles/{name}/permissions", async (
            string name,
            PermissionGrant[] grants,
            SampleDbContext db,
            SecurityRegistry registry,
            IRolePermissionCache cache,
            CancellationToken ct) =>
        {
            var role = await db.Set<Role>().SingleOrDefaultAsync(role => role.RoleName.ToUpper() == name.ToUpper(), ct);

            if (role is null)
                return Results.NotFound();

            var result = role.ApplyPermissions(grants, registry);

            if (!result.IsValid)
            {
                return Results.Problem(
                    title: "Invalid grants",
                    statusCode: StatusCodes.Status400BadRequest,
                    extensions: new Dictionary<string, object?> { ["errors"] = result.Errors });
            }

            await db.SaveChangesAsync(ct);

            // Without this the old permissions would be served from the cache until it expires.
            cache.Invalidate(role.RoleName);

            return Results.NoContent();
        });

        admin.MapGet("/users", async (SampleDbContext db, CancellationToken ct) =>
        {
            var users = await db.Set<User>().AsNoTracking().OrderBy(user => user.UserName).ToListAsync(ct);
            var roleNames = await db.Set<Role>().AsNoTracking().ToDictionaryAsync(role => role.RoleId, role => role.RoleName, ct);

            return users.Select(user => new UserDto(
                user.UserId,
                user.UserName,
                user.Email,
                user.IsActive,
                user.Roles.Select(membership => roleNames[membership.RoleId]).Order().ToList()));
        });

        admin.MapPost("/users", async (CreateUserRequest request, UserAccountService<SampleDbContext> accounts, CancellationToken ct) =>
        {
            var result = await accounts.CreateAsync(request.UserName, request.Email, request.Password, request.Roles, ct);

            return result.Succeeded
                ? Results.Created($"/admin/users/{result.User!.UserId}", new { result.User.UserId, result.User.UserName })
                : Results.Problem(
                    title: "Invalid user",
                    statusCode: StatusCodes.Status400BadRequest,
                    extensions: new Dictionary<string, object?> { ["errors"] = result.Errors });
        });

        admin.MapPost("/users/{id:guid}/deactivate", async (Guid id, UserAccountService<SampleDbContext> accounts, CancellationToken ct) =>
            await accounts.DeactivateAsync(id, ct) ? Results.NoContent() : Results.NotFound());

        return app;
    }

    private static RoleDto ToDto(Role role) => new(
        role.RoleName,
        role.Description,
        role.ResourcePermissions
            .OrderBy(permission => permission.Resource)
            .Select(permission => new GrantDto(
                permission.Resource,
                permission.AllowedActions,
                permission.FieldPermissions.ToDictionary(field => field.Field, field => field.AllowedActions)))
            .ToList());
}
