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

            var per = new ResourcePermission(res.Name);
            resPermisions.Add(per);

            foreach (var field in security.GetSecuredFields(res))
            {
                var perm = new FieldPermission(res.Name,field);

                perm.Allow(FieldsActions.Read);

                fieldPermisions.Add(perm);
            }
            
        }
        resPermisions.ForEach(p => role.AddResourcePermission(p));
        fieldPermisions.ForEach(p => role.AddFieldPermission(p));




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
    public string Resource { get; }
    public ResourceActions AllowedActions { get; private set; }

    public ResourcePermission(string resource)
    {
        Resource = resource;
        AllowedActions = ResourceActions.None;
    }

    public void Allow(params ResourceActions[] actions)
    {
        foreach (var action in actions)
        {
            if (action == ResourceActions.None ||
                (action & ~ResourceActions.All) != 0)
            {
                throw new ArgumentOutOfRangeException(nameof(actions));
            }

            AllowedActions |= action;
        }
    }

    public bool Allows(ResourceActions action) =>
        action != ResourceActions.None &&
        (action & ~ResourceActions.All) == 0 &&
        (AllowedActions & action) == action;
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
    public string Resource { get; }
    public string Field { get; }
    public FieldsActions AllowedActions { get; private set; }

    public FieldPermission(string resource, string field)
    {
        Resource = resource;
        Field = field;
        AllowedActions = FieldsActions.None;
    }

    public void Allow(params FieldsActions[] actions)
    {
        foreach (var action in actions)
        {
            if (action == FieldsActions.None ||
                (action & ~FieldsActions.All) != 0)
            {
                throw new ArgumentOutOfRangeException(nameof(actions));
            }

            AllowedActions |= action;
        }
    }

    public bool Allows(FieldsActions action) =>
        action != FieldsActions.None &&
        (action & ~FieldsActions.All) == 0 &&
        (AllowedActions & action) == action;
}

public class Role
{
    private HashSet<ResourcePermission> _resourcePermissions { get; set; } = [];
    private HashSet<FieldPermission> _feildPermissions { get; set; } = [];

    public string RoleName { get; set; }
    public string Description { get; set; }


    private Role(string RoleName, string Description)
    {
        this.RoleName = RoleName;
        this.Description = Description;
    }



    public static Role CreateRole(string RoleName, string Description)
    {
        return new(RoleName, Description);
    }


    public void AddResourcePermission(ResourcePermission permission)
    {
        _resourcePermissions.Add(permission);
    }

    public void RemoveResourcePermission(ResourcePermission permission)
    {
        _resourcePermissions.Remove(permission);
    }

    public void AddFieldPermission(FieldPermission permission)
    {
        _feildPermissions.Add(permission);
    }

    public void RemoveFieldPermission(FieldPermission permission)
    {
        _feildPermissions.Remove(permission);
    }


    public bool HasPermission(ResourcePermission permission)
    {
        return _resourcePermissions.Contains(permission);
    }

    public bool HasPermission(FieldPermission permission)
    {
        return _feildPermissions.Contains(permission);
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
    private readonly Dictionary<Type, Dictionary<string, HashSet<FieldsActions>>>
        _resources = [];

    internal void Add(
        Type resourceType,
        string propertyName,
        IEnumerable<FieldsActions> actions)
    {
        if (!_resources.TryGetValue(resourceType, out var fields))
        {
            fields = [];
            _resources[resourceType] = fields;
        }

        if (!fields.TryGetValue(propertyName, out var permissions))
        {
            permissions = [];
            fields[propertyName] = permissions;
        }

        permissions.UnionWith(actions);
    }

    public SecurityRegistry Configure<T>(
       Action<ResourceSecurityBuilder<T>> configure)
       where T : IAggregateRoot
    {
        configure(new ResourceSecurityBuilder<T>(this));
        return this;

    }

    public IEnumerable<string> GetSecuredFields(Type resourceType)
    {
        return _resources.TryGetValue(resourceType, out var fields)
            ? fields.Keys
            : [];
    }
}


public sealed class ResourceSecurityBuilder<T> where T : IAggregateRoot
{
    private readonly SecurityRegistry _registry;

    internal ResourceSecurityBuilder(SecurityRegistry registry)
    {
        _registry = registry;
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
        builder.SecureField(o => o.TotalAmmount,FieldsActions.All);
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