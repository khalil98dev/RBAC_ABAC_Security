using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SecurityBuilder.Common;
using SecurityBuilder.EntityFrameworkCore;
using SecurityBuilder.Tests.Aggregates;
using SecurityBuilder.Tests.Infrastructure;

namespace SecurityBuilder.Tests;

/// <summary>
/// A SQLite database of its own per test, seeded as the system.
///
/// Every context opened from it shares EF's internal services, so they share one compiled-query
/// cache. That is deliberate: it is the situation the read side has to be safe in.
/// </summary>
internal sealed class TestDatabase : IDisposable
{
    private readonly SqliteConnection _connection;

    public TestDatabase()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        var security = TestSecurity.Context();

        using var scope = security.RunAsSystem();
        using var db = Open(security);

        db.Database.EnsureCreated();

        var customer = Customer.Create("Khalil", "Algiers");

        var first = Order.Create(100m, customer.Id);
        first.IssueDate = new DateTime(2026, 1, 1);

        var second = Order.Create(250m, Guid.CreateVersion7());
        second.IssueDate = new DateTime(2026, 1, 2);

        var keyboard = Product.Create("Keyboard", 50m);
        var monitor = Product.Create("Monitor", 300m);

        db.AddRange(customer, first, second, keyboard, monitor);
        db.SaveChanges();

        CustomerId = customer.Id;
        OrderId = first.Id;
        ProductId = keyboard.Id;
        MonitorId = monitor.Id;
    }

    public Guid CustomerId { get; }

    public Guid OrderId { get; }

    public Guid ProductId { get; }

    public Guid MonitorId { get; }

    public AppDbContext Open(SecurityContext security) =>
        new(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .UseSecurity(security)
            .Options);

    /// <summary>A context for a fresh user, the way a scoped web request gets one.</summary>
    public AppDbContext As(params Role[] roles) => Open(TestSecurity.Context(roles));

    public decimal OrderAmount() => AsSystem(db => db.Orders.Single(order => order.Id == OrderId).TotalAmmount);

    public decimal ProductPrice() => AsSystem(db => db.Products.Single(product => product.Id == ProductId).Price);

    public string ProductName() => AsSystem(db => db.Products.Single(product => product.Id == ProductId).Name);

    public int OrderCount() => AsSystem(db => db.Orders.Count());

    public T AsSystem<T>(Func<AppDbContext, T> read)
    {
        var security = TestSecurity.Context();

        using var scope = security.RunAsSystem();
        using var db = Open(security);

        return read(db);
    }

    public void Dispose() => _connection.Dispose();
}
