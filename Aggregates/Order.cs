namespace TestPermissions.Aggregates;

public class Order : AggregateRoot
{
    public DateTime IssueDate { get; set; }

    public decimal TotalAmmount { get; set; }

    public Guid CustomerId { get; set; }

    private HashSet<OrderLines> _orderLines { get; set; }


    private Order(decimal totalAmmount, Guid customerId, HashSet<OrderLines> orderLines)
    {
        IssueDate = DateTime.Now;
        TotalAmmount = totalAmmount;
        CustomerId = customerId;
        _orderLines = orderLines;
    }



}
