using SecurityBuilder.Abstractions;
using SecurityBuilder.Tokens;

namespace SecurityBuilder.Tests.Infrastructure;

/// <summary>The users a token can be issued for. Remove one to close the account.</summary>
internal sealed class FakeTokenSubjectProvider(params TokenSubject[] subjects) : ITokenSubjectProvider
{
    public Dictionary<string, TokenSubject> Subjects { get; } =
        subjects.ToDictionary(subject => subject.UserId, StringComparer.Ordinal);

    public Task<TokenSubject?> FindAsync(string userId, CancellationToken cancellationToken = default) =>
        Task.FromResult(Subjects.TryGetValue(userId, out var subject) ? subject : null);
}
