public interface IResourceSecurityConfiguration<T> where T : IAggregateRoot
{
    void Configure(ResourceSecurityBuilder<T> builder);
}
