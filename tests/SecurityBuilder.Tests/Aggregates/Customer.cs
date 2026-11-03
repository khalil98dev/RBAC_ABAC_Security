namespace SecurityBuilder.Tests.Aggregates;

public class Customer : AggregateRoot
{

    public string Name { get; set; }

    public string AddressLine { get; set; }

    private Customer()
    {
        // EF Core
        Name = null!;
        AddressLine = null!;
    }

    private Customer(string name, string addressLien)
    {
        this.Name = name;
        AddressLine = addressLien;
    }

    public static Customer Create(string name, string addressLine) => new(name, addressLine);

}
