using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using SecurityBuilder.Common;
using SecurityBuilder.Identity;
using SecurityBuilder.Tests.Infrastructure;
using SecurityBuilder.Tokens;

namespace SecurityBuilder.Tests;

/// <summary>
/// U1-U11: accounts, signing in, and the changes that must end every session. Everything here runs
/// as an anonymous user, because signing in is what happens before anyone is signed in.
/// </summary>
public class UserAccountTests : IDisposable
{
    private const string Password = "correct-horse-battery";

    private readonly TestDatabase _database = new();
    private readonly TestClock _clock = new();
    private readonly AppDbContext _db;
    private readonly JwtOptions _options = new()
    {
        SigningKey = "a-dev-signing-key-long-enough-for-hmac-sha256",
        Issuer = "securitybuilder.tests",
        Audience = "securitybuilder.tests"
    };

    public UserAccountTests()
    {
        _database.AsSystem(db =>
        {
            db.AddRange(TestSecurity.Sales(), TestSecurity.Viewer());
            return db.SaveChanges();
        });

        _db = _database.Open(TestSecurity.Context());
    }

    // U1
    [Fact]
    public async Task A_user_is_created_in_the_named_roles()
    {
        var result = await Accounts().CreateAsync("khalil", "khalil@example.com", Password, ["sales", "Viewer"]);

        Assert.True(result.Succeeded);

        var subject = await Subjects().FindAsync(result.User!.UserId.ToString());

        Assert.NotNull(subject);
        Assert.Equal("khalil", subject.UserName);
        Assert.Equal("khalil@example.com", subject.Email);
        Assert.Equal(["Sales", "Viewer"], subject.Roles.Order());
    }

    // U2: every reason at once, like grant validation (R7), and nothing saved.
    [Fact]
    public async Task Every_reason_a_user_cannot_be_created_is_returned_together()
    {
        await Accounts().CreateAsync("khalil", null, Password, []);

        var result = await Accounts().CreateAsync("KHALIL", null, "short", ["Sales", "Nobody"]);

        Assert.False(result.Succeeded);
        Assert.Null(result.User);
        Assert.Equal(["PasswordTooShort", "UnknownRole", "UserNameTaken"], result.Errors.Select(error => error.Code).Order());
        Assert.Equal(1, _database.AsSystem(db => db.Set<User>().Count()));
    }

    // U3
    [Fact]
    public async Task The_password_is_stored_hashed()
    {
        var result = await Accounts().CreateAsync("khalil", null, Password, []);

        var stored = _database.AsSystem(db => db.Set<User>().Single()).PasswordHash;

        Assert.DoesNotContain(Password, stored, StringComparison.Ordinal);
        Assert.NotEqual(
            PasswordVerificationResult.Failed,
            new PasswordHasher<User>().VerifyHashedPassword(result.User!, stored, Password));
    }

    // U4
    [Fact]
    public async Task Signing_in_issues_a_token_for_the_user_s_roles()
    {
        var accounts = Accounts();
        await accounts.CreateAsync("khalil", null, Password, ["Sales"]);

        var pair = await accounts.SignInAsync("Khalil", Password);

        Assert.NotNull(pair);
        Assert.Equal(["Sales"], Roles(pair.AccessToken));
    }

    // U5: a wrong password, an unknown name and a closed account are the same answer.
    [Fact]
    public async Task A_failed_sign_in_does_not_say_why()
    {
        var accounts = Accounts();
        await accounts.CreateAsync("khalil", null, Password, ["Sales"]);
        await accounts.CreateAsync("closed", null, Password, ["Sales"]);
        await accounts.DeactivateAsync(_database.AsSystem(db => db.Set<User>().Single(user => user.UserName == "closed").UserId));

        Assert.Null(await accounts.SignInAsync("khalil", "wrong-password"));
        Assert.Null(await accounts.SignInAsync("nobody", Password));
        Assert.Null(await accounts.SignInAsync("closed", Password));
    }

    // U6: a hash in an older format is upgraded the next time the password is known.
    [Fact]
    public async Task An_old_hash_is_upgraded_on_sign_in()
    {
        var legacy = new PasswordHasher<User>(Options.Create(new PasswordHasherOptions
        {
            CompatibilityMode = PasswordHasherCompatibilityMode.IdentityV2
        }));

        await Accounts(legacy).CreateAsync("khalil", null, Password, ["Sales"]);

        Assert.Equal(0x00, FormatMarker());

        Assert.NotNull(await Accounts().SignInAsync("khalil", Password));

        Assert.Equal(0x01, FormatMarker());
    }

    // U7: a refresh token handed out under the old password must not outlive it.
    [Fact]
    public async Task Changing_the_password_ends_every_session()
    {
        var accounts = Accounts();
        var user = (await accounts.CreateAsync("khalil", null, Password, ["Sales"])).User!;
        var session = await accounts.SignInAsync("khalil", Password);

        Assert.True(await accounts.ChangePasswordAsync(user.UserId, Password, "a-brand-new-password"));

        await Assert.ThrowsAsync<InvalidRefreshTokenException>(() => Tokens().RefreshAsync(session!.RefreshToken));
        Assert.Null(await accounts.SignInAsync("khalil", Password));
        Assert.NotNull(await accounts.SignInAsync("khalil", "a-brand-new-password"));
    }

    // U8
    [Fact]
    public async Task The_wrong_current_password_changes_nothing()
    {
        var accounts = Accounts();
        var user = (await accounts.CreateAsync("khalil", null, Password, ["Sales"])).User!;

        Assert.False(await accounts.ChangePasswordAsync(user.UserId, "wrong-password", "a-brand-new-password"));
        Assert.NotNull(await accounts.SignInAsync("khalil", Password));
    }

    // U9: deactivating takes effect now, not when the tokens run out.
    [Fact]
    public async Task A_deactivated_account_cannot_refresh()
    {
        var accounts = Accounts();
        var user = (await accounts.CreateAsync("khalil", null, Password, ["Sales"])).User!;
        var session = await accounts.SignInAsync("khalil", Password);

        await accounts.DeactivateAsync(user.UserId);

        await Assert.ThrowsAsync<InvalidRefreshTokenException>(() => Tokens().RefreshAsync(session!.RefreshToken));
    }

    // U10: membership is by role id, so a deleted role leaves no name behind to resolve.
    [Fact]
    public async Task Deleting_a_role_removes_it_from_its_members()
    {
        var accounts = Accounts();
        var user = (await accounts.CreateAsync("khalil", null, Password, ["Sales", "Viewer"])).User!;

        _database.AsSystem(db =>
        {
            db.Remove(db.Set<Role>().Single(role => role.RoleName == "Viewer"));
            return db.SaveChanges();
        });

        var subject = await Subjects().FindAsync(user.UserId.ToString());

        Assert.Equal(["Sales"], subject!.Roles);
    }

    // U11
    [Fact]
    public async Task The_users_package_resolves_from_DI()
    {
        var services = new ServiceCollection();

        services.AddSingleton(_db);
        services.AddJwtTokens<AppDbContext>(options =>
        {
            options.SigningKey = _options.SigningKey;
            options.Issuer = _options.Issuer;
            options.Audience = _options.Audience;
        });
        services.AddUsers<AppDbContext>();

        await using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        await using var scope = provider.CreateAsyncScope();

        var accounts = scope.ServiceProvider.GetRequiredService<UserAccountService<AppDbContext>>();

        await accounts.CreateAsync("khalil", null, Password, ["Sales"]);

        Assert.NotNull(await accounts.SignInAsync("khalil", Password));
    }

    public void Dispose()
    {
        _db.Dispose();
        _database.Dispose();
    }

    private UserAccountService<AppDbContext> Accounts(IPasswordHasher<User>? hasher = null) =>
        new(_db, hasher ?? new PasswordHasher<User>(), Tokens(), Subjects(), _clock);

    private UserTokenSubjectProvider<AppDbContext> Subjects() => new(_db);

    private JwtSecurityTokenService Tokens() =>
        new(new ScopedRefreshTokenStore(_database, _clock), Subjects(), Options.Create(_options), _clock);

    private byte FormatMarker() =>
        Convert.FromBase64String(_database.AsSystem(db => db.Set<User>().AsNoTracking().Single()).PasswordHash)[0];

    private static IEnumerable<string> Roles(string accessToken) =>
        new JsonWebTokenHandler().ReadJsonWebToken(accessToken).Claims
            .Where(claim => claim.Type == ClaimTypes.Role)
            .Select(claim => claim.Value)
            .Order();
}
