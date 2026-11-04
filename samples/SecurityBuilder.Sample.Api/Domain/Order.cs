using SecurityBuilder.Abstractions;

namespace SecurityBuilder.Sample.Api.Domain;

public sealed class Order : IAggregateRoot
{
    private Order() { }

    public Guid Id { get; private set; } = Guid.CreateVersion7();

    public DateTime IssueDate { get; set; }

    public decimal TotalAmmount { get; set; }

    public Guid CustomerId { get; set; }

    public static Order Create(DateTime issueDate, decimal totalAmmount, Guid customerId) =>
        new() { IssueDate = issueDate, TotalAmmount = totalAmmount, CustomerId = customerId };
}
