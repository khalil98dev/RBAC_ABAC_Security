using Microsoft.EntityFrameworkCore;
using SecurityBuilder.EntityFrameworkCore;
using SecurityBuilder.Tests.Aggregates;

namespace SecurityBuilder.Tests.Infrastructure;

public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<Order> Orders => Set<Order>();

    public DbSet<Customer> Customers => Set<Customer>();

    public DbSet<Product> Products => Set<Product>();

    protected override void OnModelCreating(ModelBuilder modelBuilder) =>
        modelBuilder.ApplySecurityModel();
}
