using TestPermissions.Aggregates;
using TestPermissions.SecurityBuild.Actions;

public sealed class CustomerSecurityConfigurations : IResourceSecurityConfiguration<Customer>
{
    public void Configure(ResourceSecurityBuilder<Customer> builder)
    {
        builder.SecureField(c=>c.AddressLine,FieldsActions.Read);
    }
}
