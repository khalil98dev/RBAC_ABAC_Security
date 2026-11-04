using SecurityBuilder.Abstractions;

namespace SecurityBuilder.Sample.Api.Domain;

public sealed class Product : IAggregateRoot
{
    private Product() { }

    public Guid Id { get; private set; } = Guid.CreateVersion7();

    public string Name { get; set; } = default!;

    public decimal Price { get; set; }

    public static Product Create(string name, decimal price) => new() { Name = name, Price = price };
}
