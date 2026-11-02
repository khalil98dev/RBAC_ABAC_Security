using TestPermissions.Aggregates;
using TestPermissions.Common;
using TestPermissions.Permissions;
using TestPermissions.SecurityBuild.Actions;

internal class Program
{
    private static void Main(string[] args)
    {
        var security = new SecurityRegistry().AddFromAssembly(typeof(OrderSecurityConfiguration).Assembly);

        foreach (var resource in security.Resources)
        {
            Console.WriteLine($"Resource: {resource.Name} ({resource.ResourceType.Name})");
            Console.WriteLine($"Securable actions: {resource.Actions}");
            Console.WriteLine("Secured Fields: ");

            foreach (var field in resource.Fields)
            {
                Console.WriteLine($"  Field {field.Key} : Securable Actions: [{field.Value}]");
            }

            Console.WriteLine();
        }

        Console.ReadLine();


        var newRole = Role.CreateRole("User", "Limited Access");

        var orderPermission = new ResourcePermission(newRole.RoleId, "Order");

        // TODO: validate against the registry (resource exists, actions/fields are securable).
        orderPermission.Allow(ResourceActions.Read);

        orderPermission.CreateField(nameof(Order.TotalAmmount), FieldsActions.Read);

        newRole.AddResourcePermission(orderPermission);

        foreach (var permission in newRole.ResourcePermissions)
        {
            Console.WriteLine($"Role '{newRole.RoleName}' -> {permission.Resource}: {permission.AllowedActions}");

            foreach (var field in permission.FieldPermissions)
            {
                Console.WriteLine($"  {field.Field}: {field.AllowedActions}");
            }
        }

        Console.ReadLine();
    }
}
