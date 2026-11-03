using SecurityBuilder.Abstractions;

namespace SecurityBuilder.Tests.Aggregates;

public class AggregateRoot : IAggregateRoot
{
    public Guid Id { get; private set; }

    public AggregateRoot(Guid Id)
    {
        this.Id = Id;
    }

    public AggregateRoot()
    {
        Id = Guid.CreateVersion7();
    }
}
