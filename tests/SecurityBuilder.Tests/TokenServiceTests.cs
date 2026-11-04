using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using SecurityBuilder.Abstractions;
using SecurityBuilder.Actions;
using SecurityBuilder.AspNetCore;
using SecurityBuilder.Identity;
using SecurityBuilder.Tests.Aggregates;
using SecurityBuilder.Tests.Infrastructure;
using SecurityBuilder.Tokens;

namespace SecurityBuilder.Tests;

/// <summary>
/// T1-T14: issuing tokens, and the refresh chain - rotated once, reuse revokes the family, hashed in
/// the database, capped in total.
/// </summary>
public class TokenServiceTests : IDisposable
{
    private const string SigningKey = "a-dev-signing-key-long-enough-for-hmac-sha256";

    private readonly TestDatabase _database = new();
    private readonly TestClock _clock = new();
    private readonly FakeTokenSubjectProvider _subjects;
    private readonly JwtOptions _options;

    public TokenServiceTests()
    {
        _subjects = new FakeTokenSubjectProvider(Khalil("Sales"));

        _options = new JwtOptions
        {
            SigningKey = SigningKey,
            Issuer = "securitybuilder.tests",
            Audience = "securitybuilder.tests",
            RefreshTokenLifetime = TimeSpan.FromDays(7),
            RefreshTokenAbsoluteLifetime = TimeSpan.FromDays(10)
        };
    }

    // T1
    [Fact]
    public async Task An_issued_access_token_validates_and_names_the_user()
    {
        var pair = await Service().IssueAsync(Khalil("Sales", "Viewer"));

        var identity = await Validate(pair.AccessToken);

        Assert.Equal("user-1", identity.FindFirst(ClaimTypes.NameIdentifier)?.Value);
        Assert.Equal("khalil", identity.FindFirst(ClaimTypes.Name)?.Value);
        Assert.Equal("khalil@example.com", identity.FindFirst(ClaimTypes.Email)?.Value);
        Assert.Equal(_clock.Now + _options.AccessTokenLifetime, pair.AccessTokenExpiresAt);
    }

    // T2: roles travel in the token, permissions never do.
    [Fact]
    public async Task The_token_carries_role_names_and_no_permissions()
    {
        var pair = await Service().IssueAsync(Khalil("Sales", "Viewer"));

        var identity = await Validate(pair.AccessToken);

        Assert.Equal(["Sales", "Viewer"], identity.FindAll(ClaimTypes.Role).Select(claim => claim.Value).Order());
        Assert.DoesNotContain(nameof(Order.TotalAmmount), pair.AccessToken, StringComparison.OrdinalIgnoreCase);
    }

    // T3: a leaked token table must be useless, so only a hash is stored.
    [Fact]
    public async Task Only_a_hash_of_the_refresh_token_is_stored()
    {
        var pair = await Service().IssueAsync(Khalil("Sales"));

        var stored = Assert.Single(Rows());

        Assert.NotEqual(pair.RefreshToken, stored.TokenHash);
        Assert.DoesNotContain(pair.RefreshToken, stored.TokenHash, StringComparison.Ordinal);
        Assert.Equal(64, stored.TokenHash.Length);
        Assert.Equal(_clock.Now + _options.RefreshTokenLifetime, pair.RefreshTokenExpiresAt);
    }

    // T4
    [Fact]
    public async Task Refreshing_rotates_the_token_inside_one_family()
    {
        var service = Service();
        var first = await service.IssueAsync(Khalil("Sales"));

        _clock.Advance(TimeSpan.FromMinutes(20));

        var second = await service.RefreshAsync(first.RefreshToken);

        Assert.NotEqual(first.RefreshToken, second.RefreshToken);
        Assert.NotEqual(first.AccessToken, second.AccessToken);

        var rows = Rows();

        Assert.Equal(2, rows.Count);
        Assert.Single(rows.Select(row => row.FamilyId).Distinct());
        Assert.Single(rows, row => row.UsedAt is not null);
    }

    // T5: the one thing refresh tokens are for. Presented twice means the chain leaked.
    [Fact]
    public async Task Reusing_a_token_revokes_the_whole_family()
    {
        var service = Service();
        var first = await service.IssueAsync(Khalil("Sales"));

        await service.RefreshAsync(first.RefreshToken);

        var error = await Assert.ThrowsAsync<InvalidRefreshTokenException>(
            () => service.RefreshAsync(first.RefreshToken));

        Assert.Contains("already used", error.Message);
        Assert.All(Rows(), row => Assert.NotNull(row.RevokedAt));
    }

    // T6
    [Fact]
    public async Task A_revoked_token_is_refused()
    {
        var service = Service();
        var pair = await service.IssueAsync(Khalil("Sales"));

        await service.RevokeAsync(pair.RefreshToken);

        var error = await Assert.ThrowsAsync<InvalidRefreshTokenException>(
            () => service.RefreshAsync(pair.RefreshToken));

        Assert.Contains("revoked", error.Message);
    }

    // T7
    [Fact]
    public async Task An_expired_token_is_refused()
    {
        var service = Service();
        var pair = await service.IssueAsync(Khalil("Sales"));

        _clock.Advance(_options.RefreshTokenLifetime + TimeSpan.FromMinutes(1));

        var error = await Assert.ThrowsAsync<InvalidRefreshTokenException>(
            () => service.RefreshAsync(pair.RefreshToken));

        Assert.Contains("expired", error.Message);
    }

    // T8: refreshing slides the expiry forward, but never past the cap on the whole chain.
    [Fact]
    public async Task A_chain_stops_at_its_absolute_lifetime()
    {
        var service = Service();
        var start = _clock.Now;
        var first = await service.IssueAsync(Khalil("Sales"));

        _clock.Advance(TimeSpan.FromDays(5));

        var second = await service.RefreshAsync(first.RefreshToken);

        Assert.Equal(start + _options.RefreshTokenAbsoluteLifetime, second.RefreshTokenExpiresAt);

        _clock.Advance(TimeSpan.FromDays(6));

        var error = await Assert.ThrowsAsync<InvalidRefreshTokenException>(
            () => service.RefreshAsync(second.RefreshToken));

        Assert.Contains("expired", error.Message);
    }

    // T9
    [Fact]
    public async Task An_unknown_token_is_refused()
    {
        var error = await Assert.ThrowsAsync<InvalidRefreshTokenException>(
            () => Service().RefreshAsync("not-a-token"));

        Assert.Contains("Unknown", error.Message);
    }

    // T10
    [Fact]
    public async Task A_closed_account_is_refused_and_its_family_revoked()
    {
        var service = Service();
        var pair = await service.IssueAsync(Khalil("Sales"));

        _subjects.Subjects.Clear();

        await Assert.ThrowsAsync<InvalidRefreshTokenException>(() => service.RefreshAsync(pair.RefreshToken));

        Assert.All(Rows(), row => Assert.NotNull(row.RevokedAt));
    }

    // T11: the subject is read again on every refresh, so a role taken away does not live on.
    [Fact]
    public async Task A_role_taken_away_is_gone_from_the_next_token()
    {
        var service = Service();
        var first = await service.IssueAsync(Khalil("Sales", "Viewer"));

        _subjects.Subjects["user-1"] = Khalil("Viewer");

        var second = await service.RefreshAsync(first.RefreshToken);

        var identity = await Validate(second.AccessToken);

        Assert.Equal(["Viewer"], identity.FindAll(ClaimTypes.Role).Select(claim => claim.Value));
    }

    // T12: what a password change calls, so tokens handed out earlier stop working.
    [Fact]
    public async Task Revoking_a_user_ends_every_session()
    {
        var service = Service();
        var laptop = await service.IssueAsync(Khalil("Sales"));
        var phone = await service.IssueAsync(Khalil("Sales"));

        await service.RevokeAllAsync("user-1");

        await Assert.ThrowsAsync<InvalidRefreshTokenException>(() => service.RefreshAsync(laptop.RefreshToken));
        await Assert.ThrowsAsync<InvalidRefreshTokenException>(() => service.RefreshAsync(phone.RefreshToken));
    }

    // T13: a library must not ship a signing key, so it has to refuse to start without one.
    [Fact]
    public void A_missing_or_short_signing_key_refuses_to_start()
    {
        var missing = Assert.Throws<InvalidOperationException>(() => Service(new JwtOptions
        {
            Issuer = "tests",
            Audience = "tests"
        }));

        Assert.Contains("user-secrets", missing.Message);

        var tooShort = Assert.Throws<InvalidOperationException>(() => Service(new JwtOptions
        {
            SigningKey = "too-short",
            Issuer = "tests",
            Audience = "tests"
        }));

        Assert.Contains("32 bytes", tooShort.Message);
    }

    // T14: the claim types the service writes are the ones the middleware reads - the whole way round.
    [Fact]
    public async Task A_token_signs_its_user_in_through_the_middleware()
    {
        var pair = await Service().IssueAsync(Khalil("Sales"));

        var identity = await Validate(pair.AccessToken);

        var services = new ServiceCollection();
        services.AddSingleton<IRolePermissionStore>(new FakeRolePermissionStore(TestSecurity.Sales()));

        var context = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(identity),
            RequestServices = services.BuildServiceProvider()
        };

        var security = TestSecurity.Context();

        await new SecuritySignInMiddleware(_ => Task.CompletedTask)
            .InvokeAsync(context, security, Options.Create(new SecurityBuilderOptions()));

        var access = security.Access.Authorize<Order>(
            ResourceActions.Read, FieldsActions.Read, nameof(Order.TotalAmmount));

        Assert.True(access.IsAllowed);
        Assert.Empty(access.DeniedFields);
    }

    public void Dispose() => _database.Dispose();

    private ISecurityTokenService Service(JwtOptions? options = null) =>
        new JwtSecurityTokenService(
            new ScopedRefreshTokenStore(_database, _clock),
            _subjects,
            Options.Create(options ?? _options),
            _clock);

    private static TokenSubject Khalil(params string[] roles) =>
        new("user-1", "khalil", "khalil@example.com", roles);

    // Ordered in memory: SQLite refuses to ORDER BY a DateTimeOffset.
    private List<RefreshToken> Rows() =>
        _database.AsSystem(db => db.Set<RefreshToken>().ToList())
            .OrderBy(token => token.CreatedAt)
            .ToList();

    private static async Task<ClaimsIdentity> Validate(string accessToken)
    {
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(accessToken, new TokenValidationParameters
        {
            ValidIssuer = "securitybuilder.tests",
            ValidAudience = "securitybuilder.tests",
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SigningKey)),
            ClockSkew = TimeSpan.Zero
        });

        Assert.True(result.IsValid, result.Exception?.Message);

        return result.ClaimsIdentity;
    }
}
