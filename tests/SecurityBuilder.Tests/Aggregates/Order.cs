namespace SecurityBuilder.Tests.Aggregates;

public class Order : AggregateRoot
{
    public DateTime IssueDate { get; set; }

    public decimal TotalAmmount { get; set; }

    public Guid CustomerId { get; set; }

    private HashSet<OrderLines> _orderLines { get; set; }


    private Order()
    {
        // EF Core
        _orderLines = [];
    }

    private Order(decimal totalAmmount, Guid customerId, HashSet<OrderLines> orderLines)
    {
        IssueDate = DateTime.Now;
        TotalAmmount = totalAmmount;
        CustomerId = customerId;
        _orderLines = orderLines;
    }

    public static Order Create(decimal totalAmmount, Guid customerId) => new(totalAmmount, customerId, []);



}
