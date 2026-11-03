using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Diagnostics;
using SecurityBuilder.Actions;
using SecurityBuilder.Evaluation;

namespace SecurityBuilder.EntityFrameworkCore;

/// <summary>
/// Checks every change before it is saved:
///   Added    => Create + field Set on the fields that have a value
///   Modified => Set    + field Set on the modified fields
///   Deleted  => Delete
/// Throws AccessDeniedException and saves nothing when one change is not allowed.
///
/// Stateless on purpose: one instance serves every user, so EF keeps one service provider.
/// The current user comes from the DbContext, see SecurityOptionsExtension.
/// </summary>
public sealed class SecuritySaveChangesInterceptor : SaveChangesInterceptor
{
    public static readonly SecuritySaveChangesInterceptor Instance = new();

    private SecuritySaveChangesInterceptor()
    {
    }

    public override InterceptionResult<int> SavingChanges(
        DbContextEventData eventData,
        InterceptionResult<int> result)
    {
        AuthorizeChanges(eventData.Context);
        return result;
    }

    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData,
        InterceptionResult<int> result,
        CancellationToken cancellationToken = default)
    {
        AuthorizeChanges(eventData.Context);
        return ValueTask.FromResult(result);
    }

    private static void AuthorizeChanges(DbContext? context)
    {
        var security = context?.GetSecurity();

        if (context is null || security is null || security.IsSystem)
            return;

        foreach (var entry in context.ChangeTracker.Entries())
        {
            var result = AuthorizeEntry(security, entry);

            if (result is { IsAllowed: false })
                throw new AccessDeniedException(result.Reason ?? "Access denied.", result.DeniedFields);
        }
    }

    private static AccessResult? AuthorizeEntry(SecurityContext security, EntityEntry entry)
    {
        var resourceType = entry.Metadata.ClrType;

        return entry.State switch
        {
            EntityState.Added =>
                security.Access.Authorize(resourceType, ResourceActions.Create, FieldsActions.Set, FieldsWithValue(entry)),

            EntityState.Modified =>
                security.Access.Authorize(resourceType, ResourceActions.Set, FieldsActions.Set, ModifiedFields(entry)),

            EntityState.Deleted =>
                security.Access.Authorize(resourceType, ResourceActions.Delete),

            _ => null
        };
    }

    private static List<string> ModifiedFields(EntityEntry entry) =>
        entry.Properties
            .Where(property => property.IsModified)
            .Select(property => property.Metadata.Name)
            .ToList();

    private static List<string> FieldsWithValue(EntityEntry entry) =>
        entry.Properties
            .Where(property => !property.Metadata.IsPrimaryKey() && HasValue(property))
            .Select(property => property.Metadata.Name)
            .ToList();

    private static bool HasValue(PropertyEntry property)
    {
        var value = property.CurrentValue;
        if (value is null)
            return false;

        var type = property.Metadata.ClrType;
        return !type.IsValueType || !value.Equals(Activator.CreateInstance(type));
    }
}
