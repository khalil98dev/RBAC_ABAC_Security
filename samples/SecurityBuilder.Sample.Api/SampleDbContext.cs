using Microsoft.EntityFrameworkCore;
using SecurityBuilder.EntityFrameworkCore;
using SecurityBuilder.Identity;
using SecurityBuilder.Sample.Api.Domain;

namespace SecurityBuilder.Sample.Api;

public sealed class SampleDbContext(DbContextOptions<SampleDbContext> options) : DbContext(options)
{
    public DbSet<Order> Orders => Set<Order>();

    public DbSet<Product> Products => Set<Product>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Roles and permissions first: a user's membership points at a role.
        modelBuilder.ApplySecurityModel();
        modelBuilder.ApplyIdentityModel();
    }
}
