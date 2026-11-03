using SecurityBuilder.Abstractions;
using SecurityBuilder.Actions;
using SecurityBuilder.Tests.Aggregates;
using SecurityBuilder;

namespace SecurityBuilder.Tests.Configuraions;

public sealed class CustomerSecurityConfigurations : IResourceSecurityConfiguration<Customer>
{
    public void Configure(ResourceSecurityBuilder<Customer> builder)
    {
        builder.SecureField(c=>c.AddressLine,FieldsActions.Read);
    }
}
