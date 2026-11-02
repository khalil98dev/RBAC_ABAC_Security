using TestPermissions.Aggregates;
using TestPermissions.SecurityBuild.Actions;

public sealed class OrderSecurityConfiguration: IResourceSecurityConfiguration<Order>
{
    public void Configure(ResourceSecurityBuilder<Order> builder)

    {
        builder.SecureResource(ResourceActions.Read,ResourceActions.Set);

        builder.SecureField(o => o.TotalAmmount,[FieldsActions.Read,FieldsActions.Set]);

        builder.SecureField(o=>o.CustomerId,FieldsActions.Read);

        builder.SecureField(o => o.IssueDate, FieldsActions.Set);
    }
}

