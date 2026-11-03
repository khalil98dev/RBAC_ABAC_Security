using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace SecurityBuilder.EntityFrameworkCore;

/// <summary>
/// Carries the current user's <see cref="SecurityContext"/> on the DbContext options, so the
/// interceptors and the cache key generator can reach it without being built per user.
/// </summary>
public sealed class SecurityOptionsExtension(SecurityContext security) : IDbContextOptionsExtension
{
    private DbContextOptionsExtensionInfo? _info;

    public SecurityContext Security { get; } = security;

    public DbContextOptionsExtensionInfo Info => _info ??= new ExtensionInfo(this);

    public void ApplyServices(IServiceCollection services)
    {
    }

    public void Validate(IDbContextOptions options)
    {
    }

    /// <summary>
    /// Security is per user, EF's internal services are not. The hash code ignores the context
    /// so every user shares one service provider, and one compiled-query cache.
    /// </summary>
    private sealed class ExtensionInfo(IDbContextOptionsExtension extension)
        : DbContextOptionsExtensionInfo(extension)
    {
        public override bool IsDatabaseProvider => false;

        public override string LogFragment => "using SecurityBuilder ";

        public override int GetServiceProviderHashCode() => 0;

        public override bool ShouldUseSameServiceProvider(DbContextOptionsExtensionInfo other) =>
            other is ExtensionInfo;

        public override void PopulateDebugInfo(IDictionary<string, string> debugInfo) =>
            debugInfo["SecurityBuilder"] = "1";
    }
}

public static class SecurityDbContextExtensions
{
    /// <summary>The security of the user this DbContext is serving, or null when UseSecurity was not called.</summary>
    public static SecurityContext? GetSecurity(this DbContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.GetService<IDbContextOptions>()
            .FindExtension<SecurityOptionsExtension>()?
            .Security;
    }
}
