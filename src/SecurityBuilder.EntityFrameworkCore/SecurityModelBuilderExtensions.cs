using Microsoft.EntityFrameworkCore;
using SecurityBuilder.Common;
using SecurityBuilder.Permissions;

namespace SecurityBuilder.EntityFrameworkCore;

public static class SecurityModelBuilderExtensions
{
    /// <summary>
    /// Maps Role, ResourcePermission and FieldPermission. Action flags are stored as int.
    /// The unique indexes are the invariants the entities already enforce in memory: one permission
    /// per resource on a role, one permission per field on a resource.
    ///
    /// Every key is <c>ValueGeneratedNever</c>: the entities make their own ids in their constructors.
    /// Left to the convention, EF takes an entity it finds in a navigation with its key already set for
    /// one that exists, and updates it instead of inserting - which is exactly what replacing a saved
    /// role's permissions does.
    /// </summary>
    public static ModelBuilder ApplySecurityModel(this ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        modelBuilder.Entity<Role>(role =>
        {
            role.ToTable("Roles");
            role.HasKey(r => r.RoleId);
            role.Property(r => r.RoleId).ValueGeneratedNever();

            role.Property(r => r.RoleName).HasMaxLength(200).IsRequired();
            role.Property(r => r.Description).HasMaxLength(1000).IsRequired();
            role.HasIndex(r => r.RoleName).IsUnique();

            // The public ResourcePermissions is a read-only view of the private collection.
            role.Ignore(r => r.ResourcePermissions);

            role.HasMany<ResourcePermission>("_resourcePermissions")
                .WithOne()
                .HasForeignKey(permission => permission.RoleId)
                .OnDelete(DeleteBehavior.Cascade);

            // A role without its permissions tells the evaluator nothing, so it is never loaded alone.
            role.Navigation("_resourcePermissions").AutoInclude();
        });

        modelBuilder.Entity<ResourcePermission>(permission =>
        {
            permission.ToTable("ResourcePermissions");
            permission.HasKey(p => p.ResourcePermissionId);
            permission.Property(p => p.ResourcePermissionId).ValueGeneratedNever();

            permission.Property(p => p.Resource).HasMaxLength(200).IsRequired();
            permission.Property(p => p.AllowedActions).HasConversion<int>();
            permission.HasIndex(p => new { p.RoleId, p.Resource }).IsUnique();

            permission.Ignore(p => p.FieldPermissions);

            permission.HasMany<FieldPermission>("_fieldPermissions")
                .WithOne()
                .HasForeignKey(field => field.ResourcePermissionId)
                .OnDelete(DeleteBehavior.Cascade);

            permission.Navigation("_fieldPermissions").AutoInclude();
        });

        modelBuilder.Entity<FieldPermission>(field =>
        {
            field.ToTable("FieldPermissions");
            field.HasKey(f => f.ResourceFieldId);
            field.Property(f => f.ResourceFieldId).ValueGeneratedNever();

            field.Property(f => f.Field).HasMaxLength(200).IsRequired();
            field.Property(f => f.AllowedActions).HasConversion<int>();
            field.HasIndex(f => new { f.ResourcePermissionId, f.Field }).IsUnique();
        });

        return modelBuilder;
    }
}
