using SecurityBuilder.Actions;
using SecurityBuilder.Common;
using SecurityBuilder.Evaluation;
using SecurityBuilder.Grants;
using SecurityBuilder.Tests.Aggregates;

namespace SecurityBuilder.Tests;

/// <summary>The registry and the roles the tests work with.</summary>
internal static class TestSecurity
{
    /// <summary>Built once, from the configurations in this assembly: a registry is read-only after startup.</summary>
    public static SecurityRegistry Registry { get; } =
        new SecurityRegistry().AddFromAssembly(typeof(TestSecurity).Assembly);

    public static Role Guest() => Role.CreateRole("Guest", "No permissions");

    public static Role Viewer() => Build("Viewer", "Reads orders, sees amounts",
        new PermissionGrant("Order", ResourceActions.Read,
            Fields((nameof(Order.TotalAmmount), FieldsActions.Read))));

    public static Role Sales() => Build("Sales", "Reads and updates orders",
        new PermissionGrant("Order", ResourceActions.Read | ResourceActions.Set, Fields(
            (nameof(Order.TotalAmmount), FieldsActions.All),
            (nameof(Order.IssueDate), FieldsActions.Set),
            (nameof(Order.CustomerId), FieldsActions.Read))),
        new PermissionGrant("Customer", ResourceActions.None,
            Fields((nameof(Customer.AddressLine), FieldsActions.Read))),
        new PermissionGrant("Product", ResourceActions.Read,
            Fields((nameof(Product.Price), FieldsActions.Read))));

    public static Role ProductManager() => Build("ProductManager", "Manages products but not prices",
        new PermissionGrant("Product", ResourceActions.Create | ResourceActions.Read | ResourceActions.Set));

    public static Dictionary<string, FieldsActions> Fields(params (string Field, FieldsActions Actions)[] fields) =>
        fields.ToDictionary(field => field.Field, field => field.Actions);

    public static AccessEvaluator For(params Role[] roles) => new(Registry, roles);

    public static SecurityContext Context(params Role[] roles)
    {
        var security = new SecurityContext(Registry);

        if (roles.Length > 0)
            security.SignIn(roles);

        return security;
    }

    private static Role Build(string name, string description, params PermissionGrant[] grants)
    {
        var role = Role.CreateRole(name, description);
        var result = role.ApplyPermissions(grants, Registry);

        Assert.True(result.IsValid,
            $"role '{name}' is invalid: {string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}"))}");

        return role;
    }
}
