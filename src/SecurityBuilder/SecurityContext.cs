using SecurityBuilder.Common;
using SecurityBuilder.Evaluation;

namespace SecurityBuilder;

/// <summary>
/// The current user's security for one scope (one HTTP request, one background job).
/// Starts as anonymous (no roles). Register it as scoped.
/// </summary>
public sealed class SecurityContext
{
    private readonly SecurityRegistry _registry;
    private int _systemScopes;

    public SecurityContext(SecurityRegistry registry)
    {
        ArgumentNullException.ThrowIfNull(registry);

        _registry = registry;
        Access = new AccessEvaluator(registry, []);
    }

    public AccessEvaluator Access { get; private set; }

    public SecurityRegistry Registry => _registry;

    /// <summary>True inside RunAsSystem: checks are skipped (seeding, migrations, background jobs).</summary>
    public bool IsSystem => _systemScopes > 0;

    /// <summary>What this user may read. Anything cached per visibility must be keyed on it.</summary>
    public string ReadVisibility => IsSystem ? "system" : Access.ReadVisibility;

    public void SignIn(IEnumerable<Role> roles) => Access = new AccessEvaluator(_registry, roles);

    public IDisposable RunAsSystem()
    {
        _systemScopes++;
        return new SystemScope(this);
    }

    private sealed class SystemScope(SecurityContext owner) : IDisposable
    {
        private bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;
            owner._systemScopes--;
        }
    }
}
