namespace SecurityBuilder.Tests.Aggregates;

public class Product : AggregateRoot
{
    public string Name { get; set; } = default!;

    public decimal Price { get; set; }

    private Product() { }

    public static Product Create(string name, decimal price) => new() { Name = name, Price = price };
}
