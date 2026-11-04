# SecurityBuilder

A reusable library for role-based access control on resources (aggregates) plus field-level access
control. It will be reused in future projects, so the code must stay clean, simple and human-readable.

Current shape: a .NET 10 solution, `SecurityBuilder.slnx`, with the core library, the EF Core
integration, the ASP.NET Core integration, the opt-in identity package, a sample API, and 125 xUnit
tests. `dotnet test` must stay green and the
build must stay warning-free.

## Layout

| Project | Contents |
| --- | --- |
| `src/SecurityBuilder` | The core. **No dependencies at all**: no EF Core, no ASP.NET Core. |
| `src/SecurityBuilder.EntityFrameworkCore` | `Microsoft.EntityFrameworkCore` + `Microsoft.EntityFrameworkCore.Relational`, no provider. |
| `src/SecurityBuilder.AspNetCore` | DI, the sign-in middleware, `ICurrentUser` and the 403 mapping. References the core only, not EF. |
| `src/SecurityBuilder.Identity` | **Opt-in.** Users, JWT issuing and refresh tokens; `Microsoft.IdentityModel.JsonWebTokens` and `Microsoft.Extensions.Identity.Core` (for `PasswordHasher<T>` only). References the core and the EF package. Nothing else in `src` references it. |
| `src/Directory.Build.props`, `SecurityBuilder.Packages.slnf` | Package metadata for the four libraries; the filter `dotnet pack` runs on. |
| `samples/SecurityBuilder.Sample.Api` | Minimal API over SQLite wiring all four packages, with a `.http` file. Seeds three roles and demo accounts in Development. Signing key in user-secrets (`UserSecretsId` `securitybuilder-sample-api`). |
| `tests/SecurityBuilder.Tests` | xUnit, SQLite. Owns the demo domain the tests run against. |

Run the sample with `dotnet run --project samples/SecurityBuilder.Sample.Api --launch-profile http`
(port 5180). It needs `Jwt:SigningKey` in its user-secrets first.

## Packaging

The four `src` projects are NuGet packages; everything else sets `IsPackable=false`.

- `src/Directory.Build.props` holds the shared package metadata: one `VersionPrefix` for all four (they only
  work as a set), authors, repository URL, tags, the root `README.md` as the package readme, XML docs shipped
  in the package (`CS1591` off: not every public member needs a doc), and `.snupkg` symbols. The SDK adds
  Source Link for the GitHub remote by itself. Each `.csproj` adds its own `Description` and tags.
- Pack with `dotnet pack SecurityBuilder.Packages.slnf -c Release`, which writes to `artifacts/packages`
  (ignored). Pack through the filter, not the solution: the Web SDK sample warns when a solution-wide pack
  reaches it, even with `IsPackable=false`.
- Project references become package dependencies at the same version, so `SecurityBuilder.Identity 0.1.0`
  pulls `SecurityBuilder.EntityFrameworkCore 0.1.0` and `SecurityBuilder 0.1.0`.
- **Bump the version for every pack another project will restore.** NuGet caches a version forever in the
  global packages folder, so repacking 0.1.0 is silently ignored by anything that already restored it. Use
  `-p:VersionSuffix=preview.N` while iterating.
- Verified by a throwaway console project that references only the packages, restored from
  `artifacts/packages` into an isolated cache: a grant, a user, sign-in, masking and an anonymous denial all
  work from the nupkgs.
- No license is declared yet: fine for a private feed, needed before nuget.org. The id `SecurityBuilder`
  may also be taken on nuget.org.

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
| `Abstractions/ICurrentUser.cs`, `StaticCurrentUser.cs` | Who the caller is (identity), separate from `SecurityContext` (authorization). `StaticCurrentUser.Anonymous`/`.System` for jobs and seeding. |
| `Abstractions/IRolePermissionStore.cs`, `IRolePermissionCache.cs` | Role names => roles with permissions; invalidation an admin calls after editing a role. |
| `Common/RolePermissionCache.cs`, `CachedRolePermissionStore.cs` | Dictionary cache (default 5 min) and the decorator that asks the real store only for the names it is missing. A cached `Role` is shared, so treat it as read-only. |
| EF: `RolePermissionStore.cs` | Reads roles `AsNoTracking`, matched on `ToUpper()` rather than trusting the provider's collation; `AddRolePermissionStore<TContext>(cacheDuration?)` wires it behind the cache (`TimeSpan.Zero` = no cache). |
| ASP: `SecuritySignInMiddleware.cs` | `UseSecurityBuilder()`, placed after `UseAuthentication`: role claims => permissions => `SignIn`. Unauthenticated stays anonymous. |
| ASP: `SecurityBuilderOptions.cs`, `HttpContextCurrentUser.cs` | The claim types to read (role, id, name, email); `ICurrentUser` over `IHttpContextAccessor`, anonymous when there is no request. |
| ASP: `AccessDeniedExceptionHandler.cs` | `AccessDeniedException` => 403 ProblemDetails with `deniedFields`. Needs `app.UseExceptionHandler()`, which itself refuses to start without `AddProblemDetails()` or an error path - the host adds one. |
| `Abstractions/ISecurityTokenService.cs`, `Tokens/*` | Issue/refresh/revoke, `TokenSubject`, `TokenPair`, `InvalidRefreshTokenException`. Interfaces only: the core signs nothing. |
| `Abstractions/ITokenSubjectProvider.cs` | Where a user's name, email and roles come from on refresh. The seam that keeps the token service out of the user store; the application implements it. |
| Id: `JwtSecurityTokenService.cs` | HMAC-SHA256 access tokens, rotating refresh tokens. Issues only - JwtBearer still validates. Takes a `TimeProvider`. |
| Id: `RefreshToken.cs`, `IRefreshTokenStore.cs`, `EfRefreshTokenStore.cs` | One link in a chain: `Start`/`Rotate`/`MarkUsed`/`Revoke`, sliding expiry clamped to the family's cap. Each store method is one unit of work. |
| Id: `JwtOptions.cs` | Key, issuer, audience, lifetimes, claim types; `EnsureValid()` runs when the service is first resolved. |
| Id: `IdentityModelBuilderExtensions.cs`, `JwtTokenServiceCollectionExtensions.cs` | `ApplyIdentityModel()` maps `Users`, `UserRoles`, `RefreshTokens` (call it after `ApplySecurityModel`); `AddJwtTokens<TContext>(configure)` registers everything with `TryAdd`. |
| Id: `User.cs` | Account with `NormalizedUserName` (upper case, unique), membership by role id (`UserRole`), `IsActive`. The hash is set only by the account service. |
| Id: `UserAccountService.cs` | `CreateAsync` (all errors at once), `SignInAsync` (null for every failure, rehash on upgrade, constant-ish timing for unknown names), `ChangePasswordAsync` and `DeactivateAsync`, both of which revoke every session. |
| Id: `UserTokenSubjectProvider.cs`, `UserServiceCollectionExtensions.cs` | `ITokenSubjectProvider` over the users table; `AddUsers<TContext>()`. |

Tests keep the original scenario ids in comments: V1-V10 grant validation, E1-E19 evaluation,
W1-W12 writes, Q1-Q24 reads, A1-A17 sign-in and role loading, T1-T14 tokens, U1-U11 users, plus the
`ApplySecurityModel` round trip and replacing a saved role's permissions.

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
  Found in Step 5: a bare `app.UseExceptionHandler()` throws at startup unless the host also calls
  `AddProblemDetails()` or sets an error path, even with an `IExceptionHandler` registered.
- **Every key the domain generates is `ValueGeneratedNever`** (found in Step 5). Entities make their own
  `Guid` ids in their constructors; left to the convention, EF takes a new entity found in a navigation with
  its key already set for an existing one and sends an `UPDATE` (`DbUpdateConcurrencyException`, 0 rows).
  That broke replacing a saved role's permissions. Any aggregate mapped in an application has the same trap.

## Authentication (Step 5)

Decided with the owner, then built in this order. Done so far:

- Authentication: JWT bearer issued by the owner's own ASP.NET Core app (Keycloak may come later). The library
  stays authentication-agnostic: it only reads the `ClaimsPrincipal`.
- `UseSecurityBuilder()` (after `UseAuthentication`) reads the role claims, loads those roles' permissions and
  calls `SecurityContext.SignIn(roles)`. Unauthenticated => anonymous (no roles), which under R1 denies every
  secured resource. A role name with no role behind it is skipped, because a token outlives a deleted role.
- Every claim type is configurable through `AddSecurityBuilder(options => ...)` (defaults `ClaimTypes.Role`,
  `NameIdentifier`, `Name`, `Email`), so Keycloak later only changes configuration.
- **Roles in the token, permissions looked up per request.** Field-level permissions would bloat the token,
  publish the permission matrix to the client (a JWT is signed, not encrypted) and go stale until expiry.
  `IRolePermissionStore` + the cache means an admin's change takes effect on the next request.
- `ICurrentUser` is the identity view and stays apart from `SecurityContext`, the authorization view. Use it
  for audit fields. Outside a request it reports anonymous instead of throwing.

### Tokens (built in `SecurityBuilder.Identity`)

- **Users and tokens live in a separate opt-in package**, not in the core. The authorization half is
  authentication-agnostic and survives a move to Keycloak; the identity half is what Keycloak replaces
  wholesale, so the dependency must not point the other way. A project on ASP.NET Core Identity or Keycloak
  references the first three projects only.
- `ISecurityTokenService` in the core, `JwtSecurityTokenService` in the identity package, registered with
  `TryAdd` so the owner's own implementation wins.
- The signing key comes from configuration/user-secrets: there is no default and `EnsureValid()` refuses to
  start without one, or with one shorter than 32 bytes (HMAC-SHA256's minimum).
- Refresh tokens: **rotated one-time**; a token presented twice revokes the whole family, because nothing can
  tell a replay from a theft; **only a SHA-256 hash is stored** (no salt needed - the value is 256 random bits,
  not a password); `RevokeAllAsync(userId)` is the security-stamp equivalent for a password change; a sliding
  expiry per token clamped by an absolute cap per chain.
- Refresh re-reads the subject through `ITokenSubjectProvider`, so a role taken away is gone from the next
  access token and a closed account refuses the refresh and loses its family.
- Claims are written as the full `ClaimTypes` URIs the middleware reads, not the short JWT names, so a token
  round-trips whatever `JwtBearerOptions.MapInboundClaims` is set to. The defaults on both sides match;
  changing one means changing the other.
- Provider quirk: SQLite refuses to `ORDER BY` a `DateTimeOffset`, so a cleanup job over `ExpiresAt` has to
  order or compare client-side there. Nothing in the library does.

- `JwtOptions.ToValidationParameters()` gives JwtBearer the settings the service signs with, and accepts only
  HS256. The sample wires it through `AddOptions<JwtBearerOptions>().Configure<IOptions<JwtOptions>>`, so there
  is one source of truth.

### Users (built in `SecurityBuilder.Identity`)

- Hashing is `IPasswordHasher<User>` from `Microsoft.Extensions.Identity.Core`, not hand-written; a hash in an
  older format is re-hashed on the next successful sign-in.
- User names are unique on `NormalizedUserName` (upper case), not on the provider's collation.
- Sign-in returns null for a wrong password, an unknown name and a deactivated account alike, and verifies
  against a dummy hash for an unknown name, so neither the answer nor its timing says which names exist.
- Membership is by role id with a cascading foreign key, so deleting a role leaves no name behind.
- Users, roles and refresh tokens are not secured resources: they are read before anyone is signed in. The
  sample guards its admin endpoints with ASP.NET Core's `RequireRole("Admin")`.

### Sample API

- Verified end to end against the real JwtBearer pipeline: masking per role, R4/R6 on writes, R7 as 400, a
  role narrowed by an admin affecting an existing token on the next request, refresh rotation and family
  revocation, logout, password change and deactivation ending sessions.
- An access token keeps working after its family is revoked, until it expires (15 minutes by default). That
  is what stateless means; only the refresh is refused.

Not built yet, deliberately waiting on the owner's review:

- An anonymous caller on a secured resource gets **403**, not 401. 401 would tell a client to sign in; it
  changes the handler's behaviour, so it is the owner's call.
- Lockout after failed sign-ins, `ILogger` security events (reuse detected, family revoked), and recording a
  device name, user agent and IP per session.
- Nothing enforces that a role name in a token has a matching `SecurityBuilder.Role`; a startup check that
  warns about the mismatch is worth adding.
- Finding worth keeping: a per-execution parameter is **not** reachable from `IQueryExpressionInterceptor`.
  That hook runs after parameter extraction and only on a cache miss, and EF rejects any reference to the
  DbContext in the tree it returns ("reference to a constant expression of ... could cause a memory leak").
  Query filters get per-execution values because EF builds them itself and registers runtime parameters; an
  interceptor cannot. Hence the visibility-keyed cache key instead.

## Working agreement

- Work in small steps; build and run the tests after each change; never leave the build red.
- Explain trade-offs briefly and ask the owner when a decision changes behavior or public API.
- Do not commit unless the owner asks.
