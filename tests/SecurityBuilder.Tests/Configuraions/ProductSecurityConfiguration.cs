using SecurityBuilder.Abstractions;
using SecurityBuilder.Actions;
using SecurityBuilder.Tests.Aggregates;
using SecurityBuilder;

namespace SecurityBuilder.Tests.Configuraions;

public sealed class ProductSecurityConfiguration : IResourceSecurityConfiguration<Product>
{
    public void Configure(ResourceSecurityBuilder<Product> builder)
    {
        builder
            .SecureResource()                                               // no arguments => every action is secured
            .SecureField(p => p.Price, FieldsActions.Read, FieldsActions.Set);
    }
}
