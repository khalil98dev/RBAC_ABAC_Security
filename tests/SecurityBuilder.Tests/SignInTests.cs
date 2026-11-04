using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SecurityBuilder.Abstractions;
using SecurityBuilder.Actions;
using SecurityBuilder.AspNetCore;
using SecurityBuilder.Common;
using SecurityBuilder.Tests.Aggregates;
using SecurityBuilder.Tests.Infrastructure;

namespace SecurityBuilder.Tests;

/// <summary>
/// A1-A9: the middleware turns role claims into permissions, and ICurrentUser reports who the caller is.
/// </summary>
public class SignInTests
{
    // A1
    [Fact]
    public async Task An_unauthenticated_request_stays_anonymous()
    {
        var security = TestSecurity.Context();

        await SignIn(security, Anonymous(), new FakeRolePermissionStore(TestSecurity.Sales()));

        Assert.False(security.Access.Authorize<Order>(ResourceActions.Read).IsAllowed);
    }

    // A2
    [Fact]
    public async Task Role_claims_become_that_role_s_permissions()
    {
        var security = TestSecurity.Context();

        await SignIn(security, SignedIn("Sales"), new FakeRolePermissionStore(TestSecurity.Sales()));

        var access = security.Access.Authorize<Order>(
            ResourceActions.Read, FieldsActions.Read, nameof(Order.CustomerId));

        Assert.True(access.IsAllowed);
        Assert.Empty(access.DeniedFields);
    }

    // A3: several roles in the token, permissions united (R3).
    [Fact]
    public async Task Several_role_claims_are_united()
    {
        var security = TestSecurity.Context();

        await SignIn(
            security,
            SignedIn("Viewer", "ProductManager"),
            new FakeRolePermissionStore(TestSecurity.Viewer(), TestSecurity.ProductManager()));

        Assert.True(security.Access.Authorize<Order>(ResourceActions.Read).IsAllowed);
        Assert.True(security.Access.Authorize<Product>(ResourceActions.Create).IsAllowed);
    }

    // A4: the claim type is configuration, so another issuer only changes a setting.
    [Fact]
    public async Task The_role_claim_type_is_configurable()
    {
        var security = TestSecurity.Context();

        var principal = new ClaimsPrincipal(
            new ClaimsIdentity([new Claim("roles", "Sales")], authenticationType: "Test"));

        await SignIn(security, principal, new FakeRolePermissionStore(TestSecurity.Sales()),
            new SecurityBuilderOptions { RoleClaimType = "roles" });

        Assert.True(security.Access.Authorize<Order>(ResourceActions.Set).IsAllowed);
    }

    // A5: a token can outlive a role that was deleted, which must not fail the request.
    [Fact]
    public async Task An_unknown_role_name_is_skipped()
    {
        var security = TestSecurity.Context();
        var store = new FakeRolePermissionStore(TestSecurity.Viewer());

        await SignIn(security, SignedIn("Viewer", "Deleted"), store);

        Assert.Equal(["DELETED", "VIEWER"], store.Asked.Select(name => name.ToUpperInvariant()).Order());
        Assert.True(security.Access.Authorize<Order>(ResourceActions.Read).IsAllowed);
    }

    // A6
    [Fact]
    public async Task Role_claims_without_a_store_say_so()
    {
        var security = TestSecurity.Context();

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => SignIn(security, SignedIn("Sales"), store: null));

        Assert.Contains("IRolePermissionStore", error.Message);
    }

    // A7
    [Fact]
    public void The_current_user_is_read_from_the_principal()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, "7"),
            new Claim(ClaimTypes.Name, "khalil"),
            new Claim(ClaimTypes.Email, "khalil@example.com"),
            new Claim(ClaimTypes.Role, "Sales"),
            new Claim(ClaimTypes.Role, "Viewer")
        ], authenticationType: "Test"));

        var user = CurrentUser(new DefaultHttpContext { User = principal });

        Assert.True(user.IsAuthenticated);
        Assert.Equal("7", user.UserId);
        Assert.Equal("khalil", user.UserName);
        Assert.Equal("khalil@example.com", user.Email);
        Assert.Equal(["Sales", "Viewer"], user.Roles.Order());
    }

    // A8
    [Fact]
    public void An_anonymous_request_has_an_anonymous_current_user()
    {
        var user = CurrentUser(new DefaultHttpContext { User = Anonymous() });

        Assert.False(user.IsAuthenticated);
        Assert.Null(user.UserId);
        Assert.Empty(user.Roles);
    }

    // A9: a hosted service has no HttpContext, and that must not throw.
    [Fact]
    public void Outside_a_request_the_current_user_is_anonymous()
    {
        var user = CurrentUser(context: null);

        Assert.False(user.IsAuthenticated);
        Assert.Null(user.UserName);
    }

    private static Task SignIn(
        SecurityContext security,
        ClaimsPrincipal principal,
        IRolePermissionStore? store,
        SecurityBuilderOptions? options = null)
    {
        var services = new ServiceCollection();

        if (store is not null)
            services.AddSingleton(store);

        var context = new DefaultHttpContext
        {
            User = principal,
            RequestServices = services.BuildServiceProvider()
        };

        var middleware = new SecuritySignInMiddleware(_ => Task.CompletedTask);

        return middleware.InvokeAsync(context, security, Options.Create(options ?? new SecurityBuilderOptions()));
    }

    private static ICurrentUser CurrentUser(HttpContext? context) =>
        new HttpContextCurrentUser(
            new HttpContextAccessor { HttpContext = context },
            Options.Create(new SecurityBuilderOptions()));

    private static ClaimsPrincipal Anonymous() => new(new ClaimsIdentity());

    private static ClaimsPrincipal SignedIn(params string[] roles) =>
        new(new ClaimsIdentity(
            roles.Select(role => new Claim(ClaimTypes.Role, role)),
            authenticationType: "Test"));
}
