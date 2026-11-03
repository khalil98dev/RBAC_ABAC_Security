using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecurityBuilder.Actions;
using SecurityBuilder.AspNetCore;
using SecurityBuilder.EntityFrameworkCore;
using SecurityBuilder.Tests.Aggregates;
using SecurityBuilder.Tests.Infrastructure;

namespace SecurityBuilder.Tests;

/// <summary>AddSecurityBuilder and UseSecurity(serviceProvider): one registry, one user per scope.</summary>
public class DependencyInjectionTests
{
    [Fact]
    public void The_registry_is_one_frozen_singleton()
    {
        using var provider = BuildProvider();

        using var first = provider.CreateScope();
        using var second = provider.CreateScope();

        var registry = first.ServiceProvider.GetRequiredService<SecurityRegistry>();

        Assert.Same(registry, second.ServiceProvider.GetRequiredService<SecurityRegistry>());
        Assert.True(registry.IsFrozen);
    }

    [Fact]
    public void The_registry_holds_the_configurations_of_the_given_assemblies()
    {
        using var provider = BuildProvider();

        var registry = provider.GetRequiredService<SecurityRegistry>();

        Assert.Equal(["Customer", "Order", "Product"], registry.Resources.Select(r => r.Name).Order());
    }

    [Fact]
    public void A_frozen_registry_refuses_further_configuration()
    {
        using var provider = BuildProvider();

        var registry = provider.GetRequiredService<SecurityRegistry>();

        var error = Assert.Throws<InvalidOperationException>(
            () => registry.Configure<Order>(order => order.SecureResource(ResourceActions.Delete)));

        Assert.Contains("frozen", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void The_security_context_is_one_per_scope()
    {
        using var provider = BuildProvider();

        using var first = provider.CreateScope();
        using var second = provider.CreateScope();

        var context = first.ServiceProvider.GetRequiredService<SecurityContext>();

        Assert.Same(context, first.ServiceProvider.GetRequiredService<SecurityContext>());
        Assert.NotSame(context, second.ServiceProvider.GetRequiredService<SecurityContext>());
    }

    [Fact]
    public void A_new_security_context_is_anonymous()
    {
        using var provider = BuildProvider();
        using var scope = provider.CreateScope();

        var context = scope.ServiceProvider.GetRequiredService<SecurityContext>();

        Assert.False(context.IsSystem);
        Assert.False(context.Access.Authorize<Order>(ResourceActions.Read).IsAllowed);
    }

    [Fact]
    public void AddSecurityBuilder_needs_an_assembly() =>
        Assert.Throws<ArgumentException>(() => new ServiceCollection().AddSecurityBuilder());

    [Fact]
    public void Each_scope_gets_its_own_user_through_the_resolved_DbContext()
    {
        using var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();

        using var provider = BuildProvider(services =>
            services.AddDbContext<AppDbContext>((serviceProvider, options) => options
                .UseSqlite(connection)
                .UseSecurity(serviceProvider)));

        Seed(provider);

        // The scopes share one compiled-query cache, so this is the case the cache key protects.
        Assert.All(Read(provider, TestSecurity.Viewer()), customerId => Assert.Null(customerId));
        Assert.All(Read(provider, TestSecurity.Sales()), customerId => Assert.NotNull(customerId));
        Assert.All(Read(provider, TestSecurity.Viewer()), customerId => Assert.Null(customerId));
    }

    [Fact]
    public void A_denied_resource_is_denied_through_the_resolved_DbContext()
    {
        using var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();

        using var provider = BuildProvider(services =>
            services.AddDbContext<AppDbContext>((serviceProvider, options) => options
                .UseSqlite(connection)
                .UseSecurity(serviceProvider)));

        Seed(provider);

        using var scope = provider.CreateScope();

        scope.ServiceProvider.GetRequiredService<SecurityContext>().SignIn([TestSecurity.Guest()]);

        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        Assert.Throws<AccessDeniedException>(() => db.Orders.Select(order => order.Id).ToList());
    }

    private static ServiceProvider BuildProvider(Action<IServiceCollection>? configure = null)
    {
        var services = new ServiceCollection();

        services.AddSecurityBuilder(typeof(TestSecurity).Assembly);
        configure?.Invoke(services);

        return services.BuildServiceProvider();
    }

    private static void Seed(IServiceProvider provider)
    {
        using var scope = provider.CreateScope();

        var security = scope.ServiceProvider.GetRequiredService<SecurityContext>();

        using var system = security.RunAsSystem();

        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        db.Database.EnsureCreated();

        var customer = Customer.Create("Khalil", "Algiers");

        db.AddRange(customer, Order.Create(100m, customer.Id), Order.Create(250m, Guid.CreateVersion7()));
        db.SaveChanges();
    }

    private static List<Guid?> Read(IServiceProvider provider, Common.Role role)
    {
        using var scope = provider.CreateScope();

        scope.ServiceProvider.GetRequiredService<SecurityContext>().SignIn([role]);

        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        return db.Orders
            .OrderBy(order => order.TotalAmmount)
            .Select(order => new OrderDto(order.Id, order.IssueDate, order.TotalAmmount, order.CustomerId))
            .Select(dto => dto.CustomerId)
            .ToList();
    }
}
