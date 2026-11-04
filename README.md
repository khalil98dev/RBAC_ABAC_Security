# SecurityBuilder

Role-based access control on resources (aggregates), plus field-level access control, applied to
plain EF Core. You write ordinary queries and `SaveChanges`; SecurityBuilder decides what the current
user may read and change.

- A field the user may not read comes back `null` in a projection, and is never even selected.
- Filtering or sorting on a hidden field is refused, so its value cannot be inferred.
- A write that touches a field the user may not set is rejected with the list of refused fields.
- Permissions are looked up per request, so a change an admin makes applies on the next request.

## Packages

| Package | What it adds | Depends on |
| --- | --- | --- |
| `SecurityBuilder` | Registry, roles, permissions, evaluator. | nothing |
| `SecurityBuilder.EntityFrameworkCore` | The interceptors that apply it to EF Core; the role store. | EF Core |
| `SecurityBuilder.AspNetCore` | DI, the sign-in middleware, `ICurrentUser`, 403 responses. | ASP.NET Core |
| `SecurityBuilder.Identity` | **Optional.** Users, JWT access tokens, rotating refresh tokens. | the two above |

Skip `SecurityBuilder.Identity` when users come from ASP.NET Core Identity or an external provider
such as Keycloak: the rest only reads the role claims of the signed-in principal. All four share one
version; do not mix versions.

## Install

```bash
dotnet add package SecurityBuilder.AspNetCore
dotnet add package SecurityBuilder.EntityFrameworkCore
dotnet add package SecurityBuilder.Identity   # only if SecurityBuilder manages users and tokens
```

## Secure a resource

```csharp
public sealed class OrderSecurityConfiguration : IResourceSecurityConfiguration<Order>
{
    public void Configure(ResourceSecurityBuilder<Order> builder)
    {
        builder.SecureResource(ResourceActions.Read, ResourceActions.Set);

        builder.SecureField(order => order.TotalAmmount, FieldsActions.Read, FieldsActions.Set);
        builder.SecureField(order => order.CustomerId, FieldsActions.Read);
    }
}
```

What is not configured stays open; what is configured is denied until a role grants it.

## Wire it up

```csharp
builder.Services.AddSecurityBuilder(typeof(Program).Assembly);

builder.Services.AddDbContext<AppDbContext>((services, options) => options
    .UseSqlServer(connectionString)
    .UseSecurity(services));                       // no DbContext pooling

builder.Services.AddRolePermissionStore<AppDbContext>();

// Only with SecurityBuilder.Identity:
builder.Services.AddJwtTokens<AppDbContext>(options => builder.Configuration.GetSection("Jwt").Bind(options));
builder.Services.AddUsers<AppDbContext>();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();
builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
    .Configure<IOptions<JwtOptions>>((bearer, jwt) => bearer.TokenValidationParameters = jwt.Value.ToValidationParameters());

builder.Services.AddProblemDetails();              // UseExceptionHandler() needs it

var app = builder.Build();

app.UseExceptionHandler();
app.UseAuthentication();
app.UseSecurityBuilder();                          // after UseAuthentication
app.UseAuthorization();
```

In `OnModelCreating`:

```csharp
modelBuilder.ApplySecurityModel();   // roles and permissions
modelBuilder.ApplyIdentityModel();   // users and refresh tokens, only with SecurityBuilder.Identity
```

The JWT signing key comes from configuration or user-secrets (`Jwt:SigningKey`, at least 32 bytes).
There is no default, and the service refuses to start without one.

## Read through a DTO

```csharp
public sealed record OrderDto(Guid Id, decimal? TotalAmmount, Guid? CustomerId);

var orders = await db.Orders
    .Select(order => new OrderDto(order.Id, order.TotalAmmount, order.CustomerId))
    .ToListAsync();
```

A field that can be hidden must be projected into a type that can hold `null`; projecting it into a
non-nullable one throws, because `0` would be indistinguishable from real data. Entities returned
without a projection are left whole: they are for commands, never for clients.

## Known limit

`ExecuteUpdate` and `ExecuteDelete` bypass both the change tracker and projections, so they are not
checked. Do not use them on secured resources.

## Sample

`samples/SecurityBuilder.Sample.Api` in the repository wires all four packages over SQLite, with a
`.http` file that walks through every rule.
