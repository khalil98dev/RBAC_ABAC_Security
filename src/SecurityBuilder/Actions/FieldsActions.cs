namespace SecurityBuilder.Actions;

[Flags]
public enum FieldsActions
{
    None = 0,
    Read = 1 << 0,
    Set = 1 << 1,

    All = Read | Set
}
