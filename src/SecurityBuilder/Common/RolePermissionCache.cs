using System.Collections.Concurrent;
using SecurityBuilder.Abstractions;

namespace SecurityBuilder.Common;

/// <summary>
/// Keeps roles with their permissions for a while, so not every request reads them again. Register it
/// as a singleton: the entries are shared by every request.
///
/// A cached <see cref="Role"/> is shared, so treat it as read-only. Admin code that changes a role
/// loads its own copy, saves it and then calls <see cref="Invalidate"/>.
///
/// It is deliberately a plain dictionary: the core has no dependencies. A host that wants a
/// distributed cache implements <see cref="IRolePermissionStore"/> over its own instead.
/// </summary>
public sealed class RolePermissionCache(TimeSpan duration) : IRolePermissionCache
{
    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.OrdinalIgnoreCase);

    public static TimeSpan DefaultDuration { get; } = TimeSpan.FromMinutes(5);

    public RolePermissionCache() : this(DefaultDuration) { }

    public bool TryGet(string roleName, out Role? role)
    {
        role = null;

        if (!_entries.TryGetValue(roleName, out var entry))
            return false;

        if (entry.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            Invalidate(roleName);
            return false;
        }

        role = entry.Role;
        return true;
    }

    public void Set(Role role)
    {
        ArgumentNullException.ThrowIfNull(role);

        _entries[role.RoleName] = new Entry(role, DateTimeOffset.UtcNow + duration);
    }

    public void Invalidate(string roleName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(roleName);

        _entries.TryRemove(roleName, out _);
    }

    public void Clear() => _entries.Clear();

    private sealed record Entry(Role Role, DateTimeOffset ExpiresAt);
}
