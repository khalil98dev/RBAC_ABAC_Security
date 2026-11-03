using Microsoft.EntityFrameworkCore;

namespace SecurityBuilder.Identity;

public static class IdentityModelBuilderExtensions
{
    /// <summary>
    /// Maps the refresh token table. Call it from <c>OnModelCreating</c>, next to
    /// <c>ApplySecurityModel()</c>.
    /// </summary>
    public static ModelBuilder ApplyIdentityModel(this ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        modelBuilder.Entity<RefreshToken>(token =>
        {
            token.ToTable("RefreshTokens");
            token.HasKey(refresh => refresh.RefreshTokenId);

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
