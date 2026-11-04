using Microsoft.EntityFrameworkCore;
using SecurityBuilder.Actions;
using SecurityBuilder.Common;
using SecurityBuilder.Grants;
using SecurityBuilder.Identity;
using SecurityBuilder.Sample.Api.Domain;

namespace SecurityBuilder.Sample.Api;

/// <summary>
/// Creates the database and fills it once: three roles that see different fields, one demo account
/// per role, and a few orders and products. Development only.
/// </summary>
internal static class SampleSeed
{
    public static async Task RunAsync(WebApplication app)
    {
        await using var scope = app.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;

        // Seeding writes secured resources before anyone exists who could be allowed to.
        using var system = services.GetRequiredService<SecurityContext>().RunAsSystem();

        var db = services.GetRequiredService<SampleDbContext>();

        await db.Database.EnsureCreatedAsync();

        if (await db.Set<Role>().AnyAsync())
            return;

        var registry = services.GetRequiredService<SecurityRegistry>();

        db.AddRange(Viewer(registry), Sales(registry), Admin(registry));

        db.AddRange(
            Order.Create(new DateTime(2026, 1, 5), 120m, Guid.CreateVersion7()),
            Order.Create(new DateTime(2026, 2, 9), 480m, Guid.CreateVersion7()),
            Order.Create(new DateTime(2026, 3, 14), 75m, Guid.CreateVersion7()),
            Product.Create("Keyboard", 50m),
            Product.Create("Monitor", 300m));

        await db.SaveChangesAsync();

        var password = app.Configuration["Seed:Password"]
            ?? throw new InvalidOperationException("Set Seed:Password to create the demo accounts.");

        var accounts = services.GetRequiredService<UserAccountService<SampleDbContext>>();

        foreach (var (userName, role) in new[] { ("viewer", "Viewer"), ("sales", "Sales"), ("admin", "Admin") })
        {
            var result = await accounts.CreateAsync(userName, $"{userName}@example.com", password, [role]);

            if (!result.Succeeded)
                throw new InvalidOperationException(string.Join("; ", result.Errors.Select(error => error.Message)));
        }
    }

    /// <summary>Reads orders and their amounts, nothing else. Products are visible, prices are not.</summary>
    private static Role Viewer(SecurityRegistry registry) => Build(registry, "Viewer", "Reads orders and amounts",
        new PermissionGrant("Order", ResourceActions.Read, Fields((nameof(Order.TotalAmmount), FieldsActions.Read))),
        new PermissionGrant("Product", ResourceActions.Read));

    /// <summary>Reads and changes orders, sees customers and prices.</summary>
    private static Role Sales(SecurityRegistry registry) => Build(registry, "Sales", "Reads and updates orders",
        new PermissionGrant("Order", ResourceActions.Read | ResourceActions.Set, Fields(
            (nameof(Order.TotalAmmount), FieldsActions.All),
            (nameof(Order.IssueDate), FieldsActions.Set),
            (nameof(Order.CustomerId), FieldsActions.Read))),
        new PermissionGrant("Product", ResourceActions.Read, Fields((nameof(Product.Price), FieldsActions.Read))));

    /// <summary>
    /// Everything that is secured - and only that: granting an action the configuration leaves open is
    /// refused, so Create and Delete on orders are not listed. The admin endpoints check this role by name.
    /// </summary>
    private static Role Admin(SecurityRegistry registry) => Build(registry, "Admin", "Everything",
        new PermissionGrant("Order", ResourceActions.Read | ResourceActions.Set, Fields(
            (nameof(Order.TotalAmmount), FieldsActions.All),
            (nameof(Order.IssueDate), FieldsActions.Set),
            (nameof(Order.CustomerId), FieldsActions.Read))),
        new PermissionGrant("Product", ResourceActions.All, Fields((nameof(Product.Price), FieldsActions.All))));

    private static Dictionary<string, FieldsActions> Fields(params (string Field, FieldsActions Actions)[] fields) =>
        fields.ToDictionary(field => field.Field, field => field.Actions);

    private static Role Build(SecurityRegistry registry, string name, string description, params PermissionGrant[] grants)
    {
        var role = Role.CreateRole(name, description);
        var result = role.ApplyPermissions(grants, registry);

        if (!result.IsValid)
            throw new InvalidOperationException(string.Join("; ", result.Errors.Select(error => error.Message)));

        return role;
    }
}
