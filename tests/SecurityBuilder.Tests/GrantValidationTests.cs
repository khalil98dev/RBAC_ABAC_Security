using SecurityBuilder.Actions;
using SecurityBuilder.Common;
using SecurityBuilder.Grants;
using SecurityBuilder.Tests.Aggregates;

namespace SecurityBuilder.Tests;

/// <summary>Scenarios V1-V10: what the registry accepts as a grant (R7).</summary>
public class GrantValidationTests
{
    private static SecurityRegistry Registry => TestSecurity.Registry;

    [Fact] // V1
    public void Valid_grant_is_accepted()
    {
        var role = Role.CreateRole("Test", "Validation tests");

        var result = role.ApplyPermissions(
        [
            new PermissionGrant("Order", ResourceActions.Read,
                TestSecurity.Fields((nameof(Order.TotalAmmount), FieldsActions.Read)))
        ], Registry);

        Assert.True(result.IsValid);
        Assert.Equal("Order:Read", Describe(role));
    }

    [Fact] // V2
    public void Resource_and_field_names_are_case_insensitive()
    {
        var result = Registry.ValidateGrant(new PermissionGrant("order", ResourceActions.Read,
            TestSecurity.Fields(("totalammount", FieldsActions.Read))));

        Assert.True(result.IsValid);
    }

    [Fact] // V3
    public void Unknown_resource_is_rejected()
    {
        var result = Registry.ValidateGrant(new PermissionGrant("Ordr", ResourceActions.Read));

        Assert.Equal(["resource.unknown"], Codes(result));
    }

    [Fact] // V4
    public void Action_the_resource_does_not_secure_is_rejected()
    {
        // Order secures only Read and Set.
        var result = Registry.ValidateGrant(new PermissionGrant("Order", ResourceActions.Create));

        Assert.Equal(["resource.action_not_secured"], Codes(result));
    }

    [Fact] // V5
    public void Unknown_field_is_rejected()
    {
        var result = Registry.ValidateGrant(new PermissionGrant("Order", ResourceActions.Read,
            TestSecurity.Fields(("OrderId", FieldsActions.Read))));

        Assert.Equal(["field.unknown"], Codes(result));
    }

    [Fact] // V6
    public void Field_action_the_resource_does_not_secure_is_rejected()
    {
        // IssueDate secures Set only.
        var result = Registry.ValidateGrant(new PermissionGrant("Order", ResourceActions.Read,
            TestSecurity.Fields((nameof(Order.IssueDate), FieldsActions.Read))));

        Assert.Equal(["field.action_not_secured"], Codes(result));
    }

    [Fact] // V7
    public void Resource_action_is_rejected_when_only_fields_are_secured()
    {
        var result = Registry.ValidateGrant(new PermissionGrant("Customer", ResourceActions.Read));

        Assert.Equal(["resource.action_not_secured"], Codes(result));
    }

    [Fact] // V8
    public void Field_only_grant_with_no_resource_action_is_accepted()
    {
        var result = Registry.ValidateGrant(new PermissionGrant("Customer", ResourceActions.None,
            TestSecurity.Fields((nameof(Customer.AddressLine), FieldsActions.Read))));

        Assert.True(result.IsValid);
    }

    [Fact] // V9
    public void Every_error_is_returned_at_once()
    {
        var result = Registry.ValidateGrants(
        [
            new PermissionGrant("Ordr", ResourceActions.Read),
            new PermissionGrant("Order", ResourceActions.Create,
                TestSecurity.Fields(("OrderId", FieldsActions.Read))),
            new PermissionGrant("Order", ResourceActions.Read)
        ]);

        Assert.Equal(
            ["field.unknown", "resource.action_not_secured", "resource.duplicate", "resource.unknown"],
            Codes(result));
    }

    [Fact] // V10
    public void Role_is_unchanged_when_a_grant_is_invalid()
    {
        var role = Role.CreateRole("Test", "Validation tests");

        role.ApplyPermissions(
        [
            new PermissionGrant("Order", ResourceActions.Read,
                TestSecurity.Fields((nameof(Order.TotalAmmount), FieldsActions.Read)))
        ], Registry);

        var failed = role.ApplyPermissions(
        [
            new PermissionGrant("Ordr", ResourceActions.Read),
            new PermissionGrant("Order", ResourceActions.Create)
        ], Registry);

        Assert.False(failed.IsValid);
        Assert.Equal("Order:Read", Describe(role));
    }

    private static string[] Codes(SecurityValidationResult result) =>
        result.Errors.Select(error => error.Code).Order().ToArray();

    private static string Describe(Role role) =>
        string.Join(" | ", role.ResourcePermissions.Select(p => $"{p.Resource}:{p.AllowedActions}"));
}
