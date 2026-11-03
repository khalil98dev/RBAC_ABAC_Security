using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using SecurityBuilder.Abstractions;
using SecurityBuilder.Tokens;

namespace SecurityBuilder.Identity;

/// <summary>
/// Signs access tokens with HMAC-SHA256 and hands out rotating refresh tokens.
///
/// This library only issues tokens; validating them is the host's job through JwtBearer, which is why
/// nothing here reads one back. The access token carries role names, never permissions: those are
/// looked up per request, so an admin's change does not wait for the token to expire.
/// </summary>
public sealed class JwtSecurityTokenService : ISecurityTokenService
{
    private readonly IRefreshTokenStore _store;
    private readonly ITokenSubjectProvider _subjects;
    private readonly TimeProvider _clock;
    private readonly JwtOptions _options;
    private readonly SigningCredentials _signing;
    private readonly JsonWebTokenHandler _handler = new();

    public JwtSecurityTokenService(
        IRefreshTokenStore store,
        ITokenSubjectProvider subjects,
        IOptions<JwtOptions> options,
        TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(subjects);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(clock);

        _store = store;
        _subjects = subjects;
        _clock = clock;
        _options = options.Value;

        _options.EnsureValid();

        _signing = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SigningKey)),
            SecurityAlgorithms.HmacSha256);
    }

    public async Task<TokenPair> IssueAsync(TokenSubject subject, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(subject);

        var now = _clock.GetUtcNow();
        var (value, hash) = NewRefreshToken();

        var refreshToken = RefreshToken.Start(
            subject.UserId, hash, now, _options.RefreshTokenLifetime, _options.RefreshTokenAbsoluteLifetime);

        await _store.AddAsync(refreshToken, cancellationToken);

        return Pair(subject, now, value, refreshToken);
    }

    public async Task<TokenPair> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(refreshToken);

        var now = _clock.GetUtcNow();

        var stored = await _store.FindAsync(Hash(refreshToken), cancellationToken)
            ?? throw new InvalidRefreshTokenException("Unknown refresh token.");

        if (stored.UsedAt is not null)
        {
            // Presented twice: either it was stolen or the client replayed it, and from here nothing
            // tells the two apart. The whole chain is suspect, so all of it goes.
            await _store.RevokeFamilyAsync(stored.FamilyId, cancellationToken);

            throw new InvalidRefreshTokenException(
                "This refresh token was already used. Every token in its family has been revoked.");
        }

        if (stored.RevokedAt is not null)
            throw new InvalidRefreshTokenException("This refresh token was revoked.");

        if (stored.IsExpired(now))
            throw new InvalidRefreshTokenException("This refresh token has expired.");

        // Read again rather than trusted from the old token: a role taken away, or an account closed,
        // takes effect on the next refresh.
        var subject = await _subjects.FindAsync(stored.UserId, cancellationToken);

        if (subject is null)
        {
            await _store.RevokeFamilyAsync(stored.FamilyId, cancellationToken);

            throw new InvalidRefreshTokenException("This user may no longer sign in.");
        }

        var (value, hash) = NewRefreshToken();
        var replacement = stored.Rotate(hash, now, _options.RefreshTokenLifetime);

        stored.MarkUsed(now);

        await _store.RotateAsync(stored, replacement, cancellationToken);

        return Pair(subject, now, value, replacement);
    }

    public async Task RevokeAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(refreshToken);

        var stored = await _store.FindAsync(Hash(refreshToken), cancellationToken);

        // Silent when there is nothing to revoke: signing out is not a way to ask what exists.
        if (stored is not null)
            await _store.RevokeFamilyAsync(stored.FamilyId, cancellationToken);
    }

    public Task RevokeAllAsync(string userId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);

        return _store.RevokeUserAsync(userId, cancellationToken);
    }

    private TokenPair Pair(TokenSubject subject, DateTimeOffset now, string refreshValue, RefreshToken stored)
    {
        var expiresAt = now + _options.AccessTokenLifetime;

        return new TokenPair(CreateAccessToken(subject, now, expiresAt), expiresAt, refreshValue, stored.ExpiresAt);
    }

    private string CreateAccessToken(TokenSubject subject, DateTimeOffset now, DateTimeOffset expiresAt)
    {
        Dictionary<string, object> claims = new()
        {
            [_options.UserIdClaimType] = subject.UserId
        };

        if (!string.IsNullOrWhiteSpace(subject.UserName))
            claims[_options.UserNameClaimType] = subject.UserName;

        if (!string.IsNullOrWhiteSpace(subject.Email))
            claims[_options.EmailClaimType] = subject.Email;

        if (subject.Roles.Count > 0)
            claims[_options.RoleClaimType] = subject.Roles.ToArray();

        return _handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _options.Issuer,
            Audience = _options.Audience,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = expiresAt.UtcDateTime,
            SigningCredentials = _signing,
            Claims = claims
        });
    }

    /// <summary>
    /// 256 random bits, so the value needs no salt when hashed: it is not guessable to begin with,
    /// which is what separates it from a password.
    /// </summary>
    private static (string Value, string Hash) NewRefreshToken()
    {
        var value = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));

        return (value, Hash(value));
    }

    private static string Hash(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
