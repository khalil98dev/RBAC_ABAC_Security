using Microsoft.EntityFrameworkCore;
using SecurityBuilder.Common;

namespace SecurityBuilder.Identity;

public static class IdentityModelBuilderExtensions
{
    /// <summary>
    /// Maps users, their role memberships and refresh tokens. Call it from <c>OnModelCreating</c> after
    /// <c>ApplySecurityModel()</c>: a membership points at a SecurityBuilder role.
    /// </summary>
    public static ModelBuilder ApplyIdentityModel(this ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        modelBuilder.Entity<User>(user =>
        {
            user.ToTable("Users");
            user.HasKey(account => account.UserId);

            // The entities make their own ids; see ApplySecurityModel for why EF must not assume otherwise.
            user.Property(account => account.UserId).ValueGeneratedNever();

            user.Property(account => account.UserName).IsRequired().HasMaxLength(256);
            user.Property(account => account.NormalizedUserName).IsRequired().HasMaxLength(256);
            user.HasIndex(account => account.NormalizedUserName).IsUnique();

            user.Property(account => account.Email).HasMaxLength(256);
            user.Property(account => account.PasswordHash).IsRequired().HasMaxLength(512);

            user.Ignore(account => account.Roles);

            user.HasMany<UserRole>("_roles")
                .WithOne()
                .HasForeignKey(membership => membership.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            user.Navigation("_roles").AutoInclude();
        });

        modelBuilder.Entity<UserRole>(membership =>
        {
            membership.ToTable("UserRoles");
            membership.HasKey(role => new { role.UserId, role.RoleId });

            // Deleting a role removes its members rather than leaving names nothing resolves.
            membership.HasOne<Role>()
                .WithMany()
                .HasForeignKey(role => role.RoleId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<RefreshToken>(token =>
        {
            token.ToTable("RefreshTokens");
            token.HasKey(refresh => refresh.RefreshTokenId);
            token.Property(refresh => refresh.RefreshTokenId).ValueGeneratedNever();

            token.Property(refresh => refresh.UserId).IsRequired().HasMaxLength(128);

            // SHA-256 as hex. Unique, because a collision would be a second session on one token.
            token.Property(refresh => refresh.TokenHash).IsRequired().HasMaxLength(64);
            token.HasIndex(refresh => refresh.TokenHash).IsUnique();

            // Revoking is per family, and sessions are listed per user.
            token.HasIndex(refresh => refresh.FamilyId);
            token.HasIndex(refresh => refresh.UserId);
        });

        return modelBuilder;
    }
}
