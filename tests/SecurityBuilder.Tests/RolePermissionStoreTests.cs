using SecurityBuilder.Actions;
using SecurityBuilder.Common;
using SecurityBuilder.EntityFrameworkCore;
using SecurityBuilder.Tests.Aggregates;
using SecurityBuilder.Tests.Infrastructure;

namespace SecurityBuilder.Tests;

/// <summary>
/// A10-A17: loading a role's permissions, and reusing them without reading again. Every read here is
/// anonymous on purpose: the middleware loads the roles before anyone is signed in, so a role must not
/// be a secured resource.
/// </summary>
public class RolePermissionStoreTests
{
    // A10
    [Fact]
    public async Task A_role_is_loaded_with_its_permissions()
    {
        using var database = new TestDatabase();

        Save(database, TestSecurity.Sales());

        var role = Assert.Single(await Load(database, "Sales"));

        Assert.Equal("Sales", role.RoleName);

        var order = role.ResourcePermissions.Single(permission => permission.Resource == "Order");

        Assert.Equal(ResourceActions.Read | ResourceActions.Set, order.AllowedActions);
        Assert.Equal(FieldsActions.All,
            order.FieldPermissions.Single(field => field.Field == nameof(Order.TotalAmmount)).AllowedActions);
    }

    // A11: a token's casing is not the database's casing.
    [Fact]
    public async Task Role_names_are_matched_whatever_their_case()
    {
        using var database = new TestDatabase();

        Save(database, TestSecurity.Sales());

        var roles = await Load(database, "sALES");

        Assert.Equal("Sales", Assert.Single(roles).RoleName);
    }

    // A12
    [Fact]
    public async Task Unknown_and_empty_names_yield_nothing()
    {
        using var database = new TestDatabase();

        Assert.Empty(await Load(database, "Nobody"));
        Assert.Empty(await Load(database));
        Assert.Empty(await Load(database, "  "));
    }

    // A13
    [Fact]
    public async Task A_cached_role_is_not_read_again()
    {
        var inner = new FakeRolePermissionStore(TestSecurity.Sales());
        var store = new CachedRolePermissionStore(inner, new RolePermissionCache());

        Assert.Single(await store.GetRolesAsync(["Sales"]));
        Assert.Single(await store.GetRolesAsync(["Sales"]));

        Assert.Equal(1, inner.Calls);
    }

    // A14: only the names it is missing, so one new role does not reload the others.
    [Fact]
    public async Task Only_the_missing_names_are_read()
    {
        var inner = new FakeRolePermissionStore(TestSecurity.Sales(), TestSecurity.Viewer());
        var store = new CachedRolePermissionStore(inner, new RolePermissionCache());

        await store.GetRolesAsync(["Sales"]);

        inner.Asked.Clear();

        Assert.Equal(2, (await store.GetRolesAsync(["Sales", "Viewer"])).Count);
        Assert.Equal(["Viewer"], inner.Asked);
    }

    // A15: what an admin calls after changing a role, instead of waiting for the entry to expire.
    [Fact]
    public async Task Invalidating_a_role_reads_it_again()
    {
        var inner = new FakeRolePermissionStore(TestSecurity.Sales());
        var cache = new RolePermissionCache();
        var store = new CachedRolePermissionStore(inner, cache);

        await store.GetRolesAsync(["Sales"]);

        cache.Invalidate("sales");

        await store.GetRolesAsync(["Sales"]);

        Assert.Equal(2, inner.Calls);
    }

    // A16
    [Fact]
    public async Task Clearing_the_cache_reads_everything_again()
    {
        var inner = new FakeRolePermissionStore(TestSecurity.Sales(), TestSecurity.Viewer());
        var cache = new RolePermissionCache();
        var store = new CachedRolePermissionStore(inner, cache);

        await store.GetRolesAsync(["Sales", "Viewer"]);

        cache.Clear();

        await store.GetRolesAsync(["Sales", "Viewer"]);

        Assert.Equal(2, inner.Calls);
    }

    // A17
    [Fact]
    public async Task An_entry_is_read_again_once_it_expires()
    {
        var inner = new FakeRolePermissionStore(TestSecurity.Sales());
        var store = new CachedRolePermissionStore(inner, new RolePermissionCache(TimeSpan.FromMilliseconds(1)));

        await store.GetRolesAsync(["Sales"]);

        await Task.Delay(20);

        await store.GetRolesAsync(["Sales"]);

        Assert.Equal(2, inner.Calls);
    }

    private static async Task<IReadOnlyCollection<Role>> Load(TestDatabase database, params string[] roleNames)
    {
        await using var db = database.Open(TestSecurity.Context());

        return await new RolePermissionStore<AppDbContext>(db).GetRolesAsync(roleNames);
    }

    private static void Save(TestDatabase database, Role role) =>
        database.AsSystem(db =>
        {
            db.Add(role);
            return db.SaveChanges();
        });
}
