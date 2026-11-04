using SecurityBuilder.Abstractions;
using SecurityBuilder.Identity;
using SecurityBuilder.Tokens;

namespace SecurityBuilder.Sample.Api.Endpoints;

public sealed record LoginRequest(string UserName, string Password);

public sealed record RefreshRequest(string RefreshToken);

public sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword);

internal static class AuthEndpoints
{
    public static IEndpointRouteBuilder MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var auth = app.MapGroup("/auth");

        // One answer for every failure: the response does not say whether the user name exists.
        auth.MapPost("/login", async (LoginRequest request, UserAccountService<SampleDbContext> accounts, CancellationToken ct) =>
            await accounts.SignInAsync(request.UserName, request.Password, ct) is { } tokens
                ? Results.Ok(tokens)
                : Results.Problem(title: "Unauthorized", detail: "Wrong user name or password.", statusCode: StatusCodes.Status401Unauthorized));

        auth.MapPost("/refresh", async (RefreshRequest request, ISecurityTokenService tokens, CancellationToken ct) =>
        {
            try
            {
                return Results.Ok(await tokens.RefreshAsync(request.RefreshToken, ct));
            }
            catch (InvalidRefreshTokenException refused)
            {
                return Results.Problem(title: "Unauthorized", detail: refused.Message, statusCode: StatusCodes.Status401Unauthorized);
            }
        });

        auth.MapPost("/logout", async (RefreshRequest request, ISecurityTokenService tokens, CancellationToken ct) =>
        {
            await tokens.RevokeAsync(request.RefreshToken, ct);
            return Results.NoContent();
        });

        auth.MapPost("/change-password", async (
            ChangePasswordRequest request,
            ICurrentUser user,
            UserAccountService<SampleDbContext> accounts,
            CancellationToken ct) =>
        {
            var changed = Guid.TryParse(user.UserId, out var userId)
                && await accounts.ChangePasswordAsync(userId, request.CurrentPassword, request.NewPassword, ct);

            return changed
                ? Results.NoContent()
                : Results.Problem(title: "Bad Request", detail: "Wrong current password, or the new one is too short.", statusCode: StatusCodes.Status400BadRequest);
        }).RequireAuthorization();

        // Who the token says you are, and what SecurityBuilder lets you read with it.
        app.MapGet("/me", (ICurrentUser user, SecurityContext security) => new
        {
            user.UserId,
            user.UserName,
            user.Email,
            user.Roles,
            Visibility = security.ReadVisibility
        }).RequireAuthorization();

        return app;
    }
}
