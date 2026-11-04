using SecurityBuilder.Abstractions;
using SecurityBuilder.Actions;
using SecurityBuilder.Sample.Api.Domain;

namespace SecurityBuilder.Sample.Api.Security;

public sealed class OrderSecurityConfiguration : IResourceSecurityConfiguration<Order>
{
    public void Configure(ResourceSecurityBuilder<Order> builder)
    {
        builder.SecureResource(ResourceActions.Read, ResourceActions.Set);

        builder.SecureField(order => order.TotalAmmount, FieldsActions.Read, FieldsActions.Set);
        builder.SecureField(order => order.CustomerId, FieldsActions.Read);
        builder.SecureField(order => order.IssueDate, FieldsActions.Set);
    }
}
