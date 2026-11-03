using Microsoft.EntityFrameworkCore;
using SecurityBuilder.Actions;
using SecurityBuilder.Common;
using SecurityBuilder.Grants;
using SecurityBuilder.Tests.Aggregates;

namespace SecurityBuilder.Tests;

/// <summary>ApplySecurityModel: a role and its permissions survive a round trip, flags stored as int.</summary>
public class SecurityModelTests
{
    [Fact]
    public void A_role_round_trips_with_its_resource_and_field_permissions()
    {
        using var database = new TestDatabase();

        var saved = TestSecurity.Sales();

        database.AsSystem(db =>
        {
            db.Add(saved);
            return db.SaveChanges();
        });

        var loaded = database.AsSystem(db => db.Set<Role>().Single(role => role.RoleId == saved.RoleId));

        Assert.Equal("Sales", loaded.RoleName);
        Assert.Equal(3, loaded.ResourcePermissions.Count);

        var order = loaded.ResourcePermissions.Single(permission => permission.Resource == "Order");

        Assert.Equal(ResourceActions.Read | ResourceActions.Set, order.AllowedActions);

        Assert.Equal(
            [nameof(Order.CustomerId), nameof(Order.IssueDate), nameof(Order.TotalAmmount)],
            order.FieldPermissions.Select(field => field.Field).Order());

        Assert.Equal(FieldsActions.All,
            order.FieldPermissions.Single(field => field.Field == nameof(Order.TotalAmmount)).AllowedActions);
    }

    [Fact]
    public void Action_flags_are_stored_as_int()
    {
        using var database = new TestDatabase();

        var role = TestSecurity.Viewer();

        database.AsSystem(db =>
        {
            db.Add(role);
            return db.SaveChanges();
        });

        var stored = database.AsSystem(db =>
        {
            var connection = db.Database.GetDbConnection();

            using var command = connection.CreateCommand();
            command.CommandText = "SELECT AllowedActions FROM ResourcePermissions LIMIT 1";

            return Convert.ToInt64(command.ExecuteScalar());
        });

        // Order.Read is 1 << 2.
        Assert.Equal((long)ResourceActions.Read, stored);
    }

    [Fact]
    public void A_loaded_role_can_be_evaluated_like_any_other()
    {
        using var database = new TestDatabase();

        var role = TestSecurity.Viewer();

        database.AsSystem(db =>
        {
            db.Add(role);
            return db.SaveChanges();
        });

        var loaded = database.AsSystem(db => db.Set<Role>().Single(r => r.RoleId == role.RoleId));

        var access = TestSecurity.For(loaded).Authorize<Order>(ResourceActions.Read, FieldsActions.Read);

        Assert.True(access.IsAllowed);
        Assert.Equal([nameof(Order.CustomerId)], access.DeniedFields);
    }

    [Fact]
    public void Two_roles_cannot_claim_the_same_name()
    {
        using var database = new TestDatabase();

        database.AsSystem(db =>
        {
            db.Add(Role.CreateRole("Auditor", "First"));
            return db.SaveChanges();
        });

        Assert.ThrowsAny<DbUpdateException>(() => database.AsSystem(db =>
        {
            db.Add(Role.CreateRole("Auditor", "Second"));
            return db.SaveChanges();
        }));
    }

    [Fact]
    public void An_unknown_grant_never_reaches_the_database()
    {
        using var database = new TestDatabase();

        var role = Role.CreateRole("Broken", "Invalid grant");
        var result = role.ApplyPermissions([new PermissionGrant("Ordr", ResourceActions.Read)], TestSecurity.Registry);

        Assert.False(result.IsValid);
        Assert.Empty(role.ResourcePermissions);
    }
}
