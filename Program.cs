using System.Linq.Expressions;
using System.Reflection;
using System.Security;
using System.Xml.Linq;

internal class Program
{
    private static void Main(string[] args)
    {
        var role = Role.CreateRole("Admin", "Full Access");


        var assembly = Assembly.GetExecutingAssembly();

        var resources = assembly.GetTypes()
            .Where(p => p.IsClass && typeof(AggregateRoot).IsAssignableFrom(p)
                && p != typeof(AggregateRoot)
            );

        var security = new SecurityRegistry().AddFromAssembly(typeof(OrderSecurityConfiguration).Assembly);


        List<ResourcePermission> resPermisions = []; 

        List<FieldPermission> fieldPermisions = []; 


        foreach (var res in resources)
        {
            Console.WriteLine($"Resource: {res.Name}");
            Console.WriteLine($"permissions Actions: {security.GetResourceActions(res)}");
            Console.WriteLine("Secured Fields: ");  
            foreach (var field in security.GetSecuredFields(res))
            {
                Console.WriteLine($"Feild {field.Key} : Allowed Actions: [{string.Join(',',field.Value)}]");
                          
            }
            
        }

        resPermisions.ForEach(p => role.AddResourcePermission(p));
        //fieldPermisions.ForEach(p => role.AddFieldPermission(p));




        Console.ReadLine();
        
       
    }
}


[Flags]
public enum ResourceActions
{
    None = 0,
    Create = 1 << 0,
    Delete = 1 << 1,
    Read = 1 << 2,
    Set = 1 << 3,
    All = Create | Delete | Read | Set
}


public sealed class ResourcePermission
{
    private readonly List<FieldPermission> _fieldPermissions = [];
    public Guid RoleId { get; private set; }
    public Guid ResourcePermissionId { get; private set; }
    public string Resource { get; private set; }
    public ResourceActions AllowedActions { get; private set; }

    public IReadOnlyCollection<FieldPermission> FieldPermissions =>
        _fieldPermissions.AsReadOnly();


    private ResourcePermission()
    {
       //for ef core
    }


    public ResourcePermission(Guid roleId,string resource)
    {
        if (roleId == Guid.Empty)
            throw new ArgumentException("Role ID cannot be empty.", nameof(roleId));

        ArgumentException.ThrowIfNullOrWhiteSpace(resource);
        ResourcePermissionId = Guid.CreateVersion7();
        RoleId = roleId;
        Resource = resource.Trim();
        AllowedActions = ResourceActions.None;
    }

    public void Allow(params ResourceActions[] actions)
    {
        ArgumentNullException.ThrowIfNull(actions);

        foreach (var action in actions)
        {
            if (action == ResourceActions.None ||
                (action & ~ResourceActions.All) != 0)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(actions), action, "Invalid resource action.");
            }

            AllowedActions |= action;
        }
    }

    public bool Allows(ResourceActions action)
    {
        return action != ResourceActions.None &&
                (action & ~ResourceActions.All) == 0 &&
                (AllowedActions & action) == action;
    } 

    public FieldPermission AddFieldPermission(string field)
    {
        if (_fieldPermissions.Any(x => x.Field == field))
        {
            throw new InvalidOperationException(
                $"Field permission for '{field}' already exists.");
        }

        var permission = new FieldPermission(ResourcePermissionId, field);

        _fieldPermissions.Add(permission);

        return permission;
    }

    public bool RemoveFieldPermission(Guid resourceFieldId)
    {
        var permission = _fieldPermissions
            .SingleOrDefault(x => x.ResourceFieldId == resourceFieldId);

        return permission is not null &&
               _fieldPermissions.Remove(permission);
    }

    public void Deny(params ResourceActions[] actions)
    {
        ArgumentNullException.ThrowIfNull(actions);

        foreach (var action in actions)
        {
            if (action == ResourceActions.None ||
                (action & ~ResourceActions.All) != 0)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(actions), action, "Invalid resource action.");
            }

            AllowedActions &= ~action;
        }
    }

    public bool HasPermission(Guid resourceFieldId,FieldsActions action)
    {
       return  _fieldPermissions.Any(p => p.ResourceFieldId == resourceFieldId && p.Allows(action));
    }
            

}

[Flags]
public enum FieldsActions
{
    None = 0,
    Read = 1 << 0,
    Set = 1 << 1,

    All = Read | Set
}

public sealed class FieldPermission
{
    public Guid ResourcePermissionId { get; private set; }
    public Guid ResourceFieldId { get; private set; }
    public string Field { get; private set; }

    public FieldsActions AllowedActions { get; private set; }

    private FieldPermission()
    {
       //ef core
    }

    internal FieldPermission(Guid resourcePermissionId,string field)
    {
        if (resourcePermissionId == Guid.Empty)
            throw new ArgumentException(
                "Resource permission ID cannot be empty.",
                nameof(resourcePermissionId));

        ArgumentException.ThrowIfNullOrWhiteSpace(field);
        ResourceFieldId = Guid.CreateVersion7();
        ResourcePermissionId = resourcePermissionId;
        Field = field.Trim();
        AllowedActions = FieldsActions.None;
    }

    public void Allow(params FieldsActions[] actions)
    {
        ArgumentNullException.ThrowIfNull(actions);

        foreach (var action in actions)
        {
            if (action == FieldsActions.None ||
                (action & ~FieldsActions.All) != 0)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(actions), action, "Invalid field action.");
            }

            AllowedActions |= action;
        }
    }

    public void Deny(params FieldsActions[] actions)
    {
        ArgumentNullException.ThrowIfNull(actions);

        foreach (var action in actions)
        {
            if (action == FieldsActions.None ||
                (action & ~FieldsActions.All) != 0)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(actions), action, "Invalid field action.");
            }

            AllowedActions &= ~action;
        }
    }

    public bool Allows(FieldsActions action) => action != FieldsActions.None &&
                                                (action & ~FieldsActions.All) == 0 &&
                                                (AllowedActions & action) == action;
}

public class Role
{
    private HashSet<ResourcePermission> _resourcePermissions { get; set; } = [];
    public Guid RoleId { get; set; }
    public string RoleName { get; set; }
    public string Description { get; set; }

    public IReadOnlyCollection<ResourcePermission> ResourcePermissions
       => _resourcePermissions.AsReadOnly();

    private Role() { } // EF Core


    private Role(string RoleName, string Description)
    {
        RoleId = Guid.CreateVersion7();
        this.RoleName = RoleName;
        this.Description = Description;
    }

    public static Role CreateRole(string RoleName, string Description)
    {
        return new(RoleName, Description);
    }


    public void AddResourcePermission(ResourcePermission permission)
    {
        ArgumentNullException.ThrowIfNull(permission);

        if (_resourcePermissions.Any(p => p.ResourcePermissionId == permission.ResourcePermissionId))
        {
            throw new InvalidOperationException($"A permission for resource '{permission.Resource}' already exists.");
        }

        if (permission.RoleId != RoleId)
        {
            throw new InvalidOperationException("The resource permission belongs to a different role.");
        }

        _resourcePermissions.Add(permission);
    }

    public bool RemoveResourcePermission(Guid resourceId)
    {
        var permission = _resourcePermissions.SingleOrDefault(p => p.ResourcePermissionId == resourceId);

        return permission is not null && _resourcePermissions.Remove(permission);
    }

       
}

















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

public class Order : AggregateRoot
{
    public DateTime IssueDate { get; set; } 

    public decimal TotalAmmount { get; set; } 

    public Guid CustomerId { get; set; } 

    private HashSet<OrderLines> _orderLines { get; set; } 
    

    private Order(decimal totalAmmount,Guid customerId,HashSet<OrderLines> orderLines)
    {
        IssueDate = DateTime.Now;
        CustomerId = customerId;
        _orderLines = orderLines; 
    }


    
}

public class Customer : AggregateRoot 
{

    public string Name { get; set; } 

    public string AddressLine { get; set; } 

    private Customer(string name,string addressLien) 
    {
        this.Name = name;
        AddressLine = addressLien; 
    }

}


public sealed record OrderLines(int ItemId, Guid OrderId, decimal price, int qte, decimal totalPrice); 

public sealed class SecurityRegistry
{
    private readonly Dictionary<Type, ResourceActions> _resources = []; 
    private readonly Dictionary<Type, Dictionary<string, HashSet<FieldsActions>>> _securedFields = [];

    internal void AddResource(Type resourceType,IEnumerable<ResourceActions> actions)
    {
        ArgumentNullException.ThrowIfNull(resourceType);
        ArgumentNullException.ThrowIfNull(actions);

        var configuredActions = actions.ToArray();

        if (configuredActions.Length == 0)
        {
            throw new ArgumentException(
                "At least one resource action must be specified.",
                nameof(actions));
        }


        foreach (var action in configuredActions)
        {
            if (action == ResourceActions.None ||
                (action & ~ResourceActions.All) != 0)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(actions),
                    action,
                    "The resource action contains invalid flags.");
            }
        }

        var combinedActions = configuredActions.Aggregate(ResourceActions.None,
            (current,action)=> (current|action));

        if (_resources.TryGetValue(resourceType, out var existing))
        {
            _resources[resourceType] = existing | combinedActions;
        } else
        {
            _resources.Add(resourceType, combinedActions);
        }
    }

    internal void Add(Type resourceType,string propertyName,IEnumerable<FieldsActions> actions)
    {
        ArgumentNullException.ThrowIfNull(resourceType) ;
        ArgumentException.ThrowIfNullOrWhiteSpace(propertyName);
        ArgumentNullException.ThrowIfNull(actions);


        var configuredActions = actions.ToArray();

        if (configuredActions.Length == 0)
            throw new ArgumentException(
               "At least one field action must be specified.",
               nameof(actions));

        
        foreach(var action in configuredActions)
        {
            if(action == FieldsActions.None || (action & ~FieldsActions.All )!= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(action),action, "The field action contains invalid flags.");
            }
        }

        if (!_securedFields.TryGetValue(resourceType, out var fields))
        {
            fields = [];
            _securedFields[resourceType] = fields;
        }

        if (!fields.TryGetValue(propertyName, out var permissions))
        {
            permissions = [];
            fields[propertyName] = permissions;
        }

        permissions.UnionWith(actions);
    }


    public SecurityRegistry Configure<T>(Action<ResourceSecurityBuilder<T>> configure) where T : IAggregateRoot
    {
        configure(new ResourceSecurityBuilder<T>(this));
        return this;
    }


    public IReadOnlyDictionary<string,HashSet<FieldsActions>> GetSecuredFields(Type resourceType)
    {
        return _securedFields.TryGetValue(resourceType, out var fields)
            ? fields : [];
    }

    public ResourceActions GetResourceActions(Type resourceType)
    {
        ArgumentNullException.ThrowIfNull(resourceType);

        return _resources.TryGetValue(resourceType, out var actions)
            ? actions: ResourceActions.All;
    }

}

public sealed class ResourceSecurityBuilder<T> where T : IAggregateRoot
{
    private readonly SecurityRegistry _registry;

    internal ResourceSecurityBuilder(SecurityRegistry registry)
    {
        _registry = registry;
    }


    public ResourceSecurityBuilder<T> SecureResource(
      params ResourceActions[] actions)
    {
        ArgumentNullException.ThrowIfNull(actions);

        _registry.AddResource(typeof(T), actions);

        return this;
    }

    public ResourceSecurityBuilder<T> SecureField<TValue>(
        Expression<Func<T, TValue>> selector,
        params FieldsActions[] actions)
    {
        Expression body = selector.Body;

        if (body is UnaryExpression unary)
            body = unary.Operand;

        if (body is not MemberExpression member ||
            member.Member is not PropertyInfo property ||
            property.DeclaringType != typeof(T))
        {
            throw new ArgumentException(
                "Select a property directly on the resource.",
                nameof(selector));
        }

        _registry.Add(typeof(T), property.Name, actions);

        return this;
    }


}

public interface IAggregateRoot
{
    Guid Id { get; }

}

public interface IResourceSecurityConfiguration<T>
    where T : IAggregateRoot
{
    void Configure(ResourceSecurityBuilder<T> builder);
}

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

public sealed class CustomerSecurityConfigurations : IResourceSecurityConfiguration<Customer>
{
    public void Configure(ResourceSecurityBuilder<Customer> builder)
    {
        builder.SecureField(c=>c.AddressLine,FieldsActions.Read);
    }
}

public static class SecurityConfigurationExtensions
{
    public static SecurityRegistry AddConfiguration<T>(
        this SecurityRegistry registry,
        IResourceSecurityConfiguration<T> configuration)
        where T : IAggregateRoot
    {
        registry.Configure<T>(configuration.Configure);
        return registry;
    }

    public static SecurityRegistry AddFromAssembly(
        this SecurityRegistry registry,
        Assembly assembly)
    {
        var configurations = assembly.GetTypes()
            .Where(type =>
                type is { IsClass: true, IsAbstract: false } &&
                !type.IsGenericTypeDefinition)
            .Select(type => new
            {
                Type = type,
                Interface = type.GetInterfaces()
                    .FirstOrDefault(i =>
                        i.IsGenericType &&
                        i.GetGenericTypeDefinition() ==
                        typeof(IResourceSecurityConfiguration<>))
            })
            .Where(x => x.Interface is not null);

        foreach (var item in configurations)
        {
            var configuration = Activator.CreateInstance(item.Type)
                ?? throw new InvalidOperationException(
                    $"Could not create {item.Type.FullName}.");

            var method = typeof(SecurityConfigurationExtensions)
                .GetMethod(nameof(AddConfiguration))!
                .MakeGenericMethod(item.Interface!.GetGenericArguments());

            method.Invoke(null, [registry, configuration]);
        }

        return registry;
    }
}