namespace TestPermissions.Aggregates;

public class Customer : AggregateRoot
{

    public string Name { get; set; }

    public string AddressLine { get; set; }

    private Customer(string name, string addressLien)
    {
        this.Name = name;
        AddressLine = addressLien;
    }

}
