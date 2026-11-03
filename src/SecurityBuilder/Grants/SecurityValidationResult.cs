namespace SecurityBuilder.Grants;

public sealed record SecurityError(string Code, string Message, string? Resource = null, string? Field = null);

public sealed class SecurityValidationResult
{
    private readonly List<SecurityError> _errors = [];

    public IReadOnlyList<SecurityError> Errors => _errors;

    public bool IsValid => _errors.Count == 0;

    internal void Add(SecurityError error) => _errors.Add(error);
}
