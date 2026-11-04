namespace SecurityBuilder;

public sealed class AccessDeniedException(string message, IReadOnlyList<string> deniedFields) : Exception(message)
{
    public IReadOnlyList<string> DeniedFields { get; } = deniedFields;
}
