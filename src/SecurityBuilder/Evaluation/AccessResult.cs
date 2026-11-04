namespace SecurityBuilder.Evaluation;

/// <summary>
/// IsAllowed    : the request can go on.
/// DeniedFields : fields the user may not read (return them as null) or may not set (why the request was denied).
/// </summary>
public sealed record AccessResult(bool IsAllowed, IReadOnlyList<string> DeniedFields, string? Reason)
{
    public static AccessResult Allow(IReadOnlyList<string>? deniedFields = null) =>
        new(true, deniedFields ?? Array.Empty<string>(), null);

    public static AccessResult Deny(string reason, IReadOnlyList<string>? deniedFields = null) =>
        new(false, deniedFields ?? Array.Empty<string>(), reason);

    public bool IsDenied(string field) =>
        DeniedFields.Contains(field, StringComparer.OrdinalIgnoreCase);
}
