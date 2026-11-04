using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SecurityBuilder.AspNetCore;
using SecurityBuilder.EntityFrameworkCore;
using SecurityBuilder.Identity;
using SecurityBuilder.Sample.Api;
using SecurityBuilder.Sample.Api.Endpoints;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSecurityBuilder(typeof(Program).Assembly);

// Plain EF Core, secured for the user of each request. No pooling: a pooled context outlives its user.
builder.Services.AddDbContext<SampleDbContext>((services, options) => options
    .UseSqlite(builder.Configuration.GetConnectionString("Sample"))
    .UseSecurity(services));

builder.Services.AddRolePermissionStore<SampleDbContext>();

// Tokens and users. Jwt:SigningKey comes from user-secrets; the rest from appsettings.json.
builder.Services.AddJwtTokens<SampleDbContext>(options => builder.Configuration.GetSection("Jwt").Bind(options));
builder.Services.AddUsers<SampleDbContext>();

// Validated with the very settings that sign, so issuing and checking cannot drift apart.
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();
builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
    .Configure<IOptions<JwtOptions>>((bearer, jwt) => bearer.TokenValidationParameters = jwt.Value.ToValidationParameters());

builder.Services.AddAuthorization();

// UseExceptionHandler() refuses to start without this (or an error path), even with SecurityBuilder's
// 403 handler registered. It is the host's call, which is why AddSecurityBuilder does not make it.
builder.Services.AddProblemDetails();

// Flags as names: "Read, Set" rather than 6.
builder.Services.ConfigureHttpJsonOptions(json => json.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));

var app = builder.Build();

// Fail at startup, not on the first login, when the signing key is missing.
app.Services.GetRequiredService<IOptions<JwtOptions>>().Value.EnsureValid();

if (app.Environment.IsDevelopment())
    await SampleSeed.RunAsync(app);

app.UseExceptionHandler();
app.UseAuthentication();
app.UseSecurityBuilder();
app.UseAuthorization();

app.MapAuthEndpoints();
app.MapOrderEndpoints();
app.MapAdminEndpoints();

app.Run();
