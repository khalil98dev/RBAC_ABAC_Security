namespace SecurityBuilder.Abstractions;

/// <summary>
/// Drops cached role permissions. An admin who edits a role calls this, otherwise the change would
/// only take effect when the cache entry expires.
/// </summary>
public interface IRolePermissionCache
{
    void Invalidate(string roleName);

    void Clear();
}
