using Microsoft.EntityFrameworkCore;
using SecurityBuilder.Tests.Aggregates;

namespace SecurityBuilder.Tests;

/// <summary>Scenarios W1-W12: writes checked by the SaveChanges interceptor (R8).</summary>
public class SaveChangesTests
{
    [Fact] // W1
    public void Create_is_rejected_when_a_field_may_not_be_set()
    {
        using var database = new TestDatabase();
        using var db = database.As(TestSecurity.Guest());

        db.Orders.Add(Order.Create(80m, Guid.CreateVersion7()));

        var denied = Assert.Throws<AccessDeniedException>(() => db.SaveChanges());

        Assert.Equal([nameof(Order.IssueDate), nameof(Order.TotalAmmount)], denied.DeniedFields.Order());
    }

    [Fact] // W2
    public void Create_is_allowed_when_every_field_may_be_set()
    {
        using var database = new TestDatabase();

        using (var db = database.As(TestSecurity.Sales()))
        {
            db.Orders.Add(Order.Create(80m, Guid.CreateVersion7()));
            db.SaveChanges();
        }

        Assert.Equal(3, database.OrderCount());
    }

    [Fact] // W3, W4
    public void Update_is_rejected_without_the_resource_action_and_writes_nothing()
    {
        using var database = new TestDatabase();

        using (var db = database.As(TestSecurity.Viewer()))
        {
            db.Orders.Single(order => order.Id == database.OrderId).TotalAmmount = 999m;

            var denied = Assert.Throws<AccessDeniedException>(() => db.SaveChanges());

            Assert.Empty(denied.DeniedFields);
        }

        Assert.Equal(100m, database.OrderAmount());
    }

    [Fact] // W5, W6
    public void Update_is_allowed_and_persisted_when_granted()
    {
        using var database = new TestDatabase();

        using (var db = database.As(TestSecurity.Sales()))
        {
            db.Orders.Single(order => order.Id == database.OrderId).TotalAmmount = 300m;
            db.SaveChanges();
        }

        Assert.Equal(300m, database.OrderAmount());
    }

    [Fact] // W7
    public void A_field_secured_for_read_only_can_be_set()
    {
        using var database = new TestDatabase();

        using (var db = database.As(TestSecurity.Sales()))
        {
            db.Orders.Single(order => order.Id == database.OrderId).CustomerId = Guid.CreateVersion7();
            db.SaveChanges();
        }

        Assert.NotEqual(database.CustomerId,
            database.AsSystem(db => db.Orders.Single(order => order.Id == database.OrderId).CustomerId));
    }

    [Fact] // W8
    public void Update_is_rejected_and_names_the_refused_field()
    {
        using var database = new TestDatabase();

        using (var db = database.As(TestSecurity.ProductManager()))
        {
            db.Products.Single(product => product.Id == database.ProductId).Price = 75m;

            var denied = Assert.Throws<AccessDeniedException>(() => db.SaveChanges());

            Assert.Equal([nameof(Product.Price)], denied.DeniedFields);
        }

        Assert.Equal(50m, database.ProductPrice());
    }

    [Fact] // W9
    public void An_unsecured_field_can_be_updated()
    {
        using var database = new TestDatabase();

        using (var db = database.As(TestSecurity.ProductManager()))
        {
            db.Products.Single(product => product.Id == database.ProductId).Name = "Mechanical keyboard";
            db.SaveChanges();
        }

        Assert.Equal("Mechanical keyboard", database.ProductName());
    }

    [Fact] // W10
    public void Delete_is_rejected_when_the_resource_is_fully_secured()
    {
        using var database = new TestDatabase();
        using var db = database.As(TestSecurity.Guest());

        // Guest may not even read Products (R9), so loading the product is already denied.
        var denied = Assert.Throws<AccessDeniedException>(
            () => db.Products.Remove(db.Products.Single(product => product.Id == database.ProductId)));

        Assert.Contains("Product", denied.Message);
    }

    [Fact] // W11
    public void Delete_stays_open_when_it_is_not_configured()
    {
        using var database = new TestDatabase();

        var security = TestSecurity.Context(TestSecurity.Guest());

        using (var db = database.Open(security))
        {
            // Order.Delete is open but Order.Read is not, so the load happens as the system.
            Order order;

            using (security.RunAsSystem())
                order = db.Orders.Single(o => o.Id == database.OrderId);

            db.Orders.Remove(order);
            db.SaveChanges();
        }

        Assert.Equal(1, database.OrderCount());
    }

    [Fact] // W12
    public void RunAsSystem_skips_every_check()
    {
        using var database = new TestDatabase();

        var security = TestSecurity.Context(TestSecurity.Guest());

        using (security.RunAsSystem())
        using (var db = database.Open(security))
        {
            db.Products.Single(product => product.Id == database.ProductId).Price = 60m;
            db.SaveChanges();
        }

        Assert.Equal(60m, database.ProductPrice());
    }
}
