using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage;
using SecurityBuilder.Tests.Aggregates;
using SecurityBuilder.Tests.Infrastructure;

namespace SecurityBuilder.Tests;

public sealed record OrderDto(Guid Id, DateTime IssueDate, decimal? TotalAmmount, Guid? CustomerId);

/// <summary>Scenarios Q1-Q24: reads checked and masked by the query interceptor (R9-R13).</summary>
public class QueryTests
{
    // ---- projection to a DTO, the normal case (R5) ----

    [Fact] // Q1
    public void Viewer_sees_the_amount_and_not_the_customer()
    {
        using var database = new TestDatabase();
        using var db = database.As(TestSecurity.Viewer());

        var rows = Dtos(db);

        Assert.Equal([100m, 250m], rows.Select(dto => dto.TotalAmmount));
        Assert.All(rows, dto => Assert.Null(dto.CustomerId));
    }

    [Fact] // Q2
    public void Sales_sees_everything()
    {
        using var database = new TestDatabase();
        using var db = database.As(TestSecurity.Sales());

        var rows = Dtos(db);

        Assert.Equal([100m, 250m], rows.Select(dto => dto.TotalAmmount));
        Assert.All(rows, dto => Assert.NotNull(dto.CustomerId));
    }

    [Fact] // Q3
    public void A_query_compiled_for_one_user_is_not_reused_for_another()
    {
        using var database = new TestDatabase();

        // Viewer compiles the shape, Sales compiles its own, Viewer must still be masked.
        using (var viewer = database.As(TestSecurity.Viewer()))
            Assert.All(Dtos(viewer), dto => Assert.Null(dto.CustomerId));

        using (var sales = database.As(TestSecurity.Sales()))
            Assert.All(Dtos(sales), dto => Assert.NotNull(dto.CustomerId));

        using (var viewerAgain = database.As(TestSecurity.Viewer()))
            Assert.All(Dtos(viewerAgain), dto => Assert.Null(dto.CustomerId));
    }

    [Fact] // Q4
    public void The_hidden_column_is_not_in_the_sql_at_all()
    {
        using var database = new TestDatabase();
        using var viewer = database.As(TestSecurity.Viewer());
        using var sales = database.As(TestSecurity.Sales());

        Assert.DoesNotContain("\"CustomerId\"", Sql(viewer), StringComparison.Ordinal);
        Assert.Contains("\"CustomerId\"", Sql(sales), StringComparison.Ordinal);
    }

    [Fact] // Q5
    public void An_anonymous_projection_masks_a_nullable_member()
    {
        using var database = new TestDatabase();
        using var db = database.As(TestSecurity.Viewer());

        var rows = db.Orders
            .OrderBy(order => order.TotalAmmount)
            .Select(order => new { order.TotalAmmount, CustomerId = (Guid?)order.CustomerId })
            .ToList();

        Assert.Equal([100m, 250m], rows.Select(row => row.TotalAmmount));
        Assert.All(rows, row => Assert.Null(row.CustomerId));
    }

    [Fact] // Q5b
    public void An_anonymous_projection_of_a_non_nullable_member_is_refused()
    {
        using var database = new TestDatabase();
        using var db = database.As(TestSecurity.Viewer());

        // An anonymous member takes the property's own type, so this one is Guid and cannot hold null.
        var error = Assert.Throws<InvalidOperationException>(
            () => db.Orders.Select(order => new { order.TotalAmmount, order.CustomerId }).ToList());

        Assert.Contains(nameof(Order.CustomerId), error.Message, StringComparison.Ordinal);
        Assert.Contains("Guid?", error.Message, StringComparison.Ordinal);
    }

    // ---- scalar selects (R12) ----

    [Fact] // Q6
    public void A_hidden_field_cannot_be_projected_into_a_non_nullable_type()
    {
        using var database = new TestDatabase();
        using var db = database.As(TestSecurity.ProductManager());

        var error = Assert.Throws<InvalidOperationException>(
            () => db.Products.Select(product => product.Price).ToList());

        Assert.Contains(nameof(Product.Price), error.Message, StringComparison.Ordinal);
    }

    [Fact] // Q7
    public void A_hidden_field_projected_into_a_nullable_type_becomes_null()
    {
        using var database = new TestDatabase();
        using var db = database.As(TestSecurity.ProductManager());

        var prices = db.Products.Select(product => (decimal?)product.Price).ToList();

        Assert.Equal(2, prices.Count);
        Assert.All(prices, price => Assert.Null(price));
    }

    [Fact] // Q8
    public void A_visible_field_is_projected_normally()
    {
        using var database = new TestDatabase();
        using var db = database.As(TestSecurity.Sales());

        var prices = db.Products.OrderBy(product => product.Price).Select(product => product.Price).ToList();

        Assert.Equal([50m, 300m], prices);
    }

    // ---- a hidden field cannot be used to filter or sort (R11) ----

    [Fact] // Q9
    public void Filtering_on_a_hidden_field_is_denied()
    {
        using var database = new TestDatabase();
        using var db = database.As(TestSecurity.Viewer());

        var denied = Assert.Throws<AccessDeniedException>(
            () => db.Orders.Count(order => order.CustomerId == database.CustomerId));

        Assert.Equal([nameof(Order.CustomerId)], denied.DeniedFields);
    }

    [Fact] // Q10
    public void Sorting_on_a_hidden_field_is_denied()
    {
        using var database = new TestDatabase();
        using var db = database.As(TestSecurity.ProductManager());

        var denied = Assert.Throws<AccessDeniedException>(
            () => db.Products.OrderByDescending(product => product.Price).Select(product => product.Name).ToList());

        Assert.Equal([nameof(Product.Price)], denied.DeniedFields);
    }

    [Fact] // Q11
    public void Filtering_on_a_visible_field_is_allowed()
    {
        using var database = new TestDatabase();
        using var db = database.As(TestSecurity.Sales());

        Assert.Equal(1, db.Orders.Count(order => order.CustomerId == database.CustomerId));
    }

    [Fact] // Q12
    public void Filtering_on_a_field_the_user_may_read_is_allowed()
    {
        using var database = new TestDatabase();
        using var db = database.As(TestSecurity.Viewer());

        Assert.Equal(1, db.Orders.Count(order => order.TotalAmmount > 150m));
    }

    // ---- gate 1 on reads (R10) ----

    [Fact] // Q13, Q14
    public void A_denied_resource_throws_every_time_and_is_never_cached()
    {
        using var database = new TestDatabase();

        for (var attempt = 0; attempt < 2; attempt++)
        {
            using var db = database.As(TestSecurity.Guest());

            var denied = Assert.Throws<AccessDeniedException>(() => db.Orders.Select(order => order.Id).ToList());

            Assert.Contains("Order", denied.Message, StringComparison.Ordinal);
        }
    }

    [Fact] // Q15
    public void A_resource_that_only_secures_fields_stays_readable()
    {
        using var database = new TestDatabase();
        using var db = database.As(TestSecurity.Guest());

        var row = db.Customers.Select(customer => new { customer.Name, customer.AddressLine }).Single();

        Assert.Equal("Khalil", row.Name);
        Assert.Null(row.AddressLine);
    }

    [Fact] // Q16
    public void Sales_sees_the_customer_address()
    {
        using var database = new TestDatabase();
        using var db = database.As(TestSecurity.Sales());

        var row = db.Customers.Select(customer => new { customer.Name, customer.AddressLine }).Single();

        Assert.Equal("Algiers", row.AddressLine);
    }

    // ---- the exceptions to masking ----

    [Fact] // Q17
    public void Entities_are_left_whole_because_they_are_for_commands()
    {
        using var database = new TestDatabase();
        using var db = database.As(TestSecurity.Viewer());

        var orders = db.Orders.OrderBy(order => order.TotalAmmount).ToList();

        Assert.All(orders, order => Assert.NotEqual(Guid.Empty, order.CustomerId));
    }

    [Fact] // Q18
    public void RunAsSystem_masks_nothing()
    {
        using var database = new TestDatabase();

        var security = TestSecurity.Context(TestSecurity.Guest());

        using var scope = security.RunAsSystem();
        using var db = database.Open(security);

        Assert.All(Dtos(db), dto => Assert.NotNull(dto.CustomerId));
    }

    [Fact] // Q19
    public void A_field_secured_for_set_only_is_not_masked_on_read()
    {
        using var database = new TestDatabase();
        using var db = database.As(TestSecurity.Viewer());

        var dates = db.Orders.OrderBy(order => order.TotalAmmount).Select(order => order.IssueDate).ToList();

        Assert.Equal([new DateTime(2026, 1, 1), new DateTime(2026, 1, 2)], dates);
    }

    [Fact] // Q20
    public void Roles_are_unioned_on_reads_too()
    {
        using var database = new TestDatabase();
        using var db = database.As(TestSecurity.Viewer(), TestSecurity.Sales());

        Assert.All(Dtos(db), dto => Assert.NotNull(dto.CustomerId));
    }

    // ---- the async path compiles under its own cache key ----

    [Fact] // Q22
    public async Task Masking_works_on_the_async_path()
    {
        using var database = new TestDatabase();
        using var db = database.As(TestSecurity.Viewer());

        var rows = await db.Orders
            .OrderBy(order => order.TotalAmmount)
            .Select(order => new OrderDto(order.Id, order.IssueDate, order.TotalAmmount, order.CustomerId))
            .ToListAsync();

        Assert.All(rows, dto => Assert.Null(dto.CustomerId));
    }

    [Fact] // Q23
    public async Task Gate_1_works_on_the_async_path()
    {
        using var database = new TestDatabase();
        using var db = database.As(TestSecurity.Guest());

        await Assert.ThrowsAsync<AccessDeniedException>(
            () => db.Orders.Select(order => order.Id).ToListAsync());
    }

    [Fact] // Q24
    public void Two_users_contexts_share_one_compiled_query_cache()
    {
        using var database = new TestDatabase();
        using var viewer = database.As(TestSecurity.Viewer());
        using var sales = database.As(TestSecurity.Sales());

        // Everything above only means something if the cache really is shared. A singleton EF
        // service resolving to the same instance proves both contexts use one service provider.
        Assert.Same(viewer.GetService<ITypeMappingSource>(), sales.GetService<ITypeMappingSource>());
    }

    private static List<OrderDto> Dtos(AppDbContext db) =>
        db.Orders
            .OrderBy(order => order.TotalAmmount)
            .Select(order => new OrderDto(order.Id, order.IssueDate, order.TotalAmmount, order.CustomerId))
            .ToList();

    private static string Sql(AppDbContext db) =>
        db.Orders
            .Select(order => new OrderDto(order.Id, order.IssueDate, order.TotalAmmount, order.CustomerId))
            .ToQueryString();
}
