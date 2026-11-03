# SecurityBuilder

A reusable library for role-based access control on resources (aggregates) plus field-level access
control. It will be reused in future projects, so the code must stay clean, simple and human-readable.

Current shape: a .NET 10 solution, `SecurityBuilder.slnx`, with the core library, the EF Core
integration, the ASP.NET Core integration, and 78 xUnit tests. `dotnet test` must stay green and the
build must stay warning-free.

## Layout

| Project | Contents |
| --- | --- |
| `src/SecurityBuilder` | The core. **No dependencies at all**: no EF Core, no ASP.NET Core. |
| `src/SecurityBuilder.EntityFrameworkCore` | `Microsoft.EntityFrameworkCore` + `Microsoft.EntityFrameworkCore.Relational`, no provider. |
| `src/SecurityBuilder.AspNetCore` | DI and the 403 mapping. References the core only, not EF. |
| `tests/SecurityBuilder.Tests` | xUnit, SQLite. Owns the demo domain the tests run against. |

Still to come: `samples/SecurityBuilder.Sample.Api` (Step 5), and the authentication middleware
that signs the current user in (Step 5), which is why `SecurityBuilder.AspNetCore` holds no
middleware yet.

## Pieces

| Path | Role |
| --- | --- |
| `SecurityRegistry.cs`, `ResourceDefinition.cs` | Catalog of what is securable, built once at startup from `IResourceSecurityConfiguration<T>` via `AddFromAssembly`; grant validation (`ValidateGrant`/`ValidateGrants`); `Freeze()`/`IsFrozen`, after which configuring throws and reads are thread-safe. |
| `ResourceSecurityBuilder.cs` | Fluent config: `HasName`, `SecureResource(...)`, `SecureField(...)`. |
| `Common/Role.cs`, `Permissions/*` | What a role is granted; `ApplyPermissions(grants, registry)`. |
| `Evaluation/AccessEvaluator.cs` | ONE method `Authorize<T>(action, fieldAction = None, params fields)` returning `AccessResult(IsAllowed, DeniedFields, Reason)`, plus `ReadVisibility`. |
| `SecurityContext.cs` | Scoped current-user security: anonymous by default, `SignIn(roles)`, `RunAsSystem()` bypass. |
| `Abstractions/IAggregateRoot.cs` | What a securable resource is. The interface lives in the core; the `AggregateRoot` base class is demo code and lives with the tests. |
| EF: `SecuritySaveChangesInterceptor.cs` | Writes: checks every tracked change before it is saved. Stateless singleton. |
| EF: `SecurityQueryInterceptor.cs` | Reads: gate 1 per execution, then hands the query to the rewriter. Stateless singleton. |
| EF: `FieldMaskRewriter.cs` | Rewrites hidden fields to `null` in projections, denies them in `Where`/`OrderBy`. |
| EF: `SecurityCompiledQueryCacheKeyGenerator.cs` | Puts the user's visibility in EF's query cache key. Required for the read side to be safe. |
| EF: `SecurityOptionsExtension.cs` | Carries the scope's `SecurityContext` on the DbContext options; `GetSecurity()`. |
| EF: `SecurityModelBuilderExtensions.cs` | `modelBuilder.ApplySecurityModel()`: maps Role/ResourcePermission/FieldPermission, flags as int. |
| EF: `SecurityDbContextOptionsExtensions.cs` | `UseSecurity(serviceProvider)` for DI and `UseSecurity(securityContext)` for tests and jobs; wires all of the above. |
| ASP: `SecurityBuilderServiceCollectionExtensions.cs` | `AddSecurityBuilder(params Assembly[])`: registry built, frozen and registered as a singleton; `SecurityContext` scoped; the 403 handler registered. |
| ASP: `AccessDeniedExceptionHandler.cs` | `AccessDeniedException` => 403 ProblemDetails with `deniedFields`. Needs `app.UseExceptionHandler()`. |

Tests keep the original scenario ids in comments: V1-V10 grant validation, E1-E19 evaluation,
W1-W12 writes, Q1-Q24 reads, plus the `ApplySecurityModel` round trip.

## Rules (do not change them without asking the owner)

- **R1** Not configured => open. Configuring a resource/field makes it deny-by-default.
- **R2** `SecureResource()` with no args secures ALL actions; with explicit actions only those are secured, the
  others stay open. A resource that only configures fields keeps its actions open.
- **R3** A user's permissions = union of their roles. No explicit Deny.
- **R4** Pipeline: step 1 resource action (denied => whole request denied, fields not checked); step 2 fields.
- **R5** Field Read denied => request allowed, value returned as null (never modify the entity).
- **R6** Field Set denied => whole request rejected with the list of denied fields.
- **R7** Grant validation returns ALL errors; role unchanged if any error.
- **R8** No configurable mapping from resource action to field action (no `CheckFieldsOn`); the caller/interceptor
  passes the field action explicitly. Writes: `Added` => `Create` + field `Set` on fields with a value;
  `Modified` => `Set` + field `Set` on modified fields; `Deleted` => `Delete`.
- Resource names are case-insensitive; field names are entity property names.

### Reads (decided in Steps 1-2)

- **R9** Reading is an action like any other. Loading an entity to change or delete it needs resource
  `Read`, so a role that may `Delete` but not `Read` cannot load the entity itself.
- **R10** Resource `Read` denied => `AccessDeniedException`, thrown per execution and never cached.
- **R11** A hidden field inside a `Select` projection becomes `null`. Used anywhere else - `Where`,
  `OrderBy`, aggregates - it throws `AccessDeniedException`, so a value cannot be inferred by
  filtering or sorting.
- **R12** A hidden field must be projected into a type that can hold null. Projecting one into a
  non-nullable type throws `InvalidOperationException` naming the field; masking to `default(T)` is
  never acceptable, because `0` is indistinguishable from real data. With anonymous types this means
  writing `CustomerId = (Guid?)o.CustomerId`.
- **R13** Entities returned without a projection are left whole: they are for commands. Never return
  an entity to a client; project to a DTO. Masking a materialized entity would break R5.
- The rewrite is a compile-time constant fold, and EF caches it. It is safe **only** because
  `SecurityCompiledQueryCacheKeyGenerator` adds the user's visibility to the cache key, so a cached
  plan is only ever reused by a user who reads exactly the same fields. The two always ship together.
  Plans per query shape = distinct visibility profiles, not users.
- Known hole: `ExecuteUpdate`/`ExecuteDelete` bypass both the change tracker and projections, so they
  escape security entirely. Not closed yet.

## Code style

- Clean, small methods, readable names, `HasFlag` instead of raw bit masks, short XML docs only where useful.
- Keep the owner's existing naming (including `TotalAmmount`, `FieldsActions`, the `Configuraions` folder) unless
  he agrees to rename.
- No over-engineering: no generic repositories, no mediator, no extra abstractions without a reason.
- The core library must have NO dependency on EF Core or ASP.NET Core.
- Namespaces follow the folders: `SecurityBuilder`, `SecurityBuilder.Actions`, `.Common`, `.Evaluation`,
  `.Grants`, `.Permissions`, `.Abstractions`, `SecurityBuilder.EntityFrameworkCore`.

## Wiring (done in Step 4)

- `services.AddSecurityBuilder(params Assembly[] configurationAssemblies)`: registry as a frozen singleton,
  `SecurityContext` scoped, `AccessDeniedExceptionHandler` registered.
- `options.UseSecurity(serviceProvider)` inside `AddDbContext((sp, o) => ...)`. The options extension holds a
  `Func<SecurityContext>`, not an instance, so one interceptor and one EF service provider serve every user
  while the user itself stays per scope. **No DbContext pooling**: a pooled context would outlive its user.
- `AccessDeniedException` => 403 ProblemDetails with `deniedFields`, written by the handler itself rather than
  through `IProblemDetailsService`, so `AddSecurityBuilder` does not change how the rest of the app renders errors.

## Planned decisions (Step 5)

- Authentication: JWT bearer issued by the owner's own ASP.NET Core app (Keycloak may come later). The library
  stays authentication-agnostic: it only reads the `ClaimsPrincipal`.
- Middleware (after `UseAuthentication`) reads the role claims, loads those roles' permissions and calls
  `SecurityContext.SignIn(roles)`. Unauthenticated => anonymous (no roles).
- The role claim type is configurable (default `ClaimTypes.Role`), so Keycloak later only changes configuration.
- Role permissions come from an `IRolePermissionStore` interface (EF implementation in the EF package), with
  in-memory caching per role and a way to invalidate when an admin changes a role. `ApplySecurityModel` already
  auto-includes a role's permissions, so loading a role gives the whole aggregate.
- Finding worth keeping: a per-execution parameter is **not** reachable from `IQueryExpressionInterceptor`.
  That hook runs after parameter extraction and only on a cache miss, and EF rejects any reference to the
  DbContext in the tree it returns ("reference to a constant expression of ... could cause a memory leak").
  Query filters get per-execution values because EF builds them itself and registers runtime parameters; an
  interceptor cannot. Hence the visibility-keyed cache key instead.

## Working agreement

- Work in small steps; build and run the tests after each change; never leave the build red.
- Explain trade-offs briefly and ask the owner when a decision changes behavior or public API.
- Do not commit unless the owner asks.
