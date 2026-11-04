using SecurityBuilder.Abstractions;
using SecurityBuilder.Actions;
using SecurityBuilder.Sample.Api.Domain;

namespace SecurityBuilder.Sample.Api.Security;

public sealed class ProductSecurityConfiguration : IResourceSecurityConfiguration<Product>
{
    public void Configure(ResourceSecurityBuilder<Product> builder)
    {
        builder
            .SecureResource()
            .SecureField(product => product.Price, FieldsActions.Read, FieldsActions.Set);
    }
}
