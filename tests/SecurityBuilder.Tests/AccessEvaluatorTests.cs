using SecurityBuilder.Actions;
using SecurityBuilder.Evaluation;
using SecurityBuilder.Tests.Aggregates;

namespace SecurityBuilder.Tests;

/// <summary>Scenarios E1-E19: the two gates of the pipeline (R1-R6).</summary>
public class AccessEvaluatorTests
{
    // ---- gate 1: resource actions (R1, R2, R4) ----

    [Fact] // E1
    public void Guest_cannot_read_a_secured_resource() =>
        AssertAccess(
            TestSecurity.For(TestSecurity.Guest()).Authorize<Order>(ResourceActions.Read, FieldsActions.Read),
            allowed: false);

    [Fact] // E2
    public void Unconfigured_action_stays_open() =>
        AssertAccess(
            TestSecurity.For(TestSecurity.Guest()).Authorize<Order>(ResourceActions.Create),
            allowed: true);

    [Fact] // E3
    public void Unconfigured_delete_stays_open() =>
        AssertAccess(
            TestSecurity.For(TestSecurity.Guest()).Authorize<Order>(ResourceActions.Delete),
            allowed: true);

    [Fact] // E4
    public void SecureResource_without_arguments_secures_every_action() =>
        AssertAccess(
            TestSecurity.For(TestSecurity.Guest()).Authorize<Product>(ResourceActions.Delete),
            allowed: false);

    [Fact] // E5
    public void Gate_1_denial_skips_the_fields()
    {
        // Viewer may read Order but not Set it, so the field grant is never looked at.
        var result = TestSecurity.For(TestSecurity.Viewer())
            .Authorize<Order>(ResourceActions.Set, FieldsActions.Set, nameof(Order.TotalAmmount));

        AssertAccess(result, allowed: false);
    }

    // ---- gate 2 on read: masked fields (R5) ----

    [Fact] // E6
    public void Viewer_reads_Order_with_CustomerId_hidden() =>
        AssertAccess(
            TestSecurity.For(TestSecurity.Viewer()).Authorize<Order>(ResourceActions.Read, FieldsActions.Read),
            allowed: true, nameof(Order.CustomerId));

    [Fact] // E7
    public void Sales_reads_Order_with_nothing_hidden() =>
        AssertAccess(
            TestSecurity.For(TestSecurity.Sales()).Authorize<Order>(ResourceActions.Read, FieldsActions.Read),
            allowed: true);

    [Fact] // E8
    public void A_resource_that_only_secures_fields_stays_readable() =>
        AssertAccess(
            TestSecurity.For(TestSecurity.Guest()).Authorize<Customer>(ResourceActions.Read, FieldsActions.Read),
            allowed: true, nameof(Customer.AddressLine));

    [Fact] // E9
    public void Sales_sees_the_customer_address() =>
        AssertAccess(
            TestSecurity.For(TestSecurity.Sales()).Authorize<Customer>(ResourceActions.Read, FieldsActions.Read),
            allowed: true);

    [Fact] // E10
    public void ProductManager_reads_Product_with_Price_hidden() =>
        AssertAccess(
            TestSecurity.For(TestSecurity.ProductManager()).Authorize<Product>(ResourceActions.Read, FieldsActions.Read),
            allowed: true, nameof(Product.Price));

    [Fact] // E11
    public void A_hidden_field_becomes_null_on_the_dto()
    {
        var access = TestSecurity.For(TestSecurity.Viewer())
            .Authorize<Order>(ResourceActions.Read, FieldsActions.Read);

        var totalAmmount = access.IsDenied(nameof(Order.TotalAmmount)) ? (decimal?)null : 250m;
        var customerId = access.IsDenied(nameof(Order.CustomerId)) ? (Guid?)null : Guid.CreateVersion7();

        Assert.Equal(250m, totalAmmount);
        Assert.Null(customerId);
    }

    // ---- gate 2 on write: refused fields reject the request (R6) ----

    [Fact] // E12
    public void Sales_sets_the_fields_it_is_granted() =>
        AssertAccess(
            TestSecurity.For(TestSecurity.Sales()).Authorize<Order>(
                ResourceActions.Set, FieldsActions.Set, nameof(Order.TotalAmmount), nameof(Order.IssueDate)),
            allowed: true);

    [Fact] // E13
    public void A_field_secured_for_read_only_stays_settable() =>
        AssertAccess(
            TestSecurity.For(TestSecurity.Sales()).Authorize<Order>(
                ResourceActions.Set, FieldsActions.Set, nameof(Order.CustomerId)),
            allowed: true);

    [Fact] // E14
    public void One_refused_field_rejects_the_whole_write() =>
        AssertAccess(
            TestSecurity.For(TestSecurity.ProductManager()).Authorize<Product>(
                ResourceActions.Set, FieldsActions.Set, nameof(Product.Name), nameof(Product.Price)),
            allowed: false, nameof(Product.Price));

    [Fact] // E15
    public void An_unsecured_field_stays_settable() =>
        AssertAccess(
            TestSecurity.For(TestSecurity.ProductManager()).Authorize<Product>(
                ResourceActions.Set, FieldsActions.Set, nameof(Product.Name)),
            allowed: true);

    [Fact] // E16
    public void Create_checks_field_Set_too() =>
        AssertAccess(
            TestSecurity.For(TestSecurity.ProductManager()).Authorize<Product>(
                ResourceActions.Create, FieldsActions.Set, nameof(Product.Name), nameof(Product.Price)),
            allowed: false, nameof(Product.Price));

    // ---- several roles (R3) ----

    [Fact] // E17
    public void Roles_are_unioned_but_add_nothing_they_do_not_grant() =>
        AssertAccess(
            TestSecurity.For(TestSecurity.Viewer(), TestSecurity.ProductManager())
                .Authorize<Order>(ResourceActions.Read, FieldsActions.Read),
            allowed: true, nameof(Order.CustomerId));

    [Fact] // E18
    public void A_second_role_can_bring_the_missing_action() =>
        AssertAccess(
            TestSecurity.For(TestSecurity.Viewer(), TestSecurity.Sales())
                .Authorize<Order>(ResourceActions.Set, FieldsActions.Set, nameof(Order.TotalAmmount)),
            allowed: true);

    [Fact] // E19
    public void A_field_nobody_grants_stays_refused() =>
        AssertAccess(
            TestSecurity.For(TestSecurity.Sales(), TestSecurity.ProductManager())
                .Authorize<Product>(ResourceActions.Set, FieldsActions.Set, nameof(Product.Price)),
            allowed: false, nameof(Product.Price));

    private static void AssertAccess(AccessResult result, bool allowed, params string[] deniedFields)
    {
        Assert.Equal(allowed, result.IsAllowed);
        Assert.Equal(deniedFields.Order(), result.DeniedFields.Order());
    }
}
