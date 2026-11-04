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

builder.Services.AddSecurityBuilder(typeof(Program).Assembly); // For Build the Security Register  

builder.Services.AddDbContext<SampleDbContext>((services, options) => options
    .UseSqlite(builder.Configuration.GetConnectionString("Sample"))
    .UseSecurity(services));

builder.Services.AddRolePermissionStore<SampleDbContext>();


builder.Services.AddJwtTokens<SampleDbContext>(options => builder.Configuration.GetSection("Jwt").Bind(options));
builder.Services.AddUsers<SampleDbContext>();


builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();
builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
    .Configure<IOptions<JwtOptions>>((bearer, jwt) => bearer.TokenValidationParameters = jwt.Value.ToValidationParameters());

builder.Services.AddAuthorization();


builder.Services.AddProblemDetails();


builder.Services.ConfigureHttpJsonOptions(json => json.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));

var app = builder.Build();

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
