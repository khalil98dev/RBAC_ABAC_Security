namespace TestPermissions.SecurityBuild.Actions;

[Flags]
public enum ResourceActions
{
    None = 0,
    Create = 1 << 0,
    Delete = 1 << 1,
    Read = 1 << 2,
    Set = 1 << 3,
    All = Create | Delete | Read | Set
}

