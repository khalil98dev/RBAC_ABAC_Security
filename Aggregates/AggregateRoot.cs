public class AggregateRoot : IAggregateRoot
{
    public Guid Id { get;  } 

    public AggregateRoot(Guid Id)
    {
        this.Id = Id;
    }

    public AggregateRoot()
    {
        Id = Guid.CreateVersion7();
    }
}
