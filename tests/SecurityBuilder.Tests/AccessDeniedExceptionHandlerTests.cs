using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using SecurityBuilder.AspNetCore;

namespace SecurityBuilder.Tests;

/// <summary>AccessDeniedException becomes 403 ProblemDetails, listing the refused fields.</summary>
public class AccessDeniedExceptionHandlerTests
{
    [Fact]
    public async Task A_denial_becomes_403_problem_details()
    {
        var context = NewHttpContext();

        var handled = await new AccessDeniedExceptionHandler().TryHandleAsync(
            context,
            new AccessDeniedException("Missing 'Read' permission on 'Order'.", []),
            CancellationToken.None);

        Assert.True(handled);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);

        var problem = await ReadBody(context);

        Assert.Equal("Forbidden", problem.GetProperty("title").GetString());
        Assert.Equal(403, problem.GetProperty("status").GetInt32());
        Assert.Equal("Missing 'Read' permission on 'Order'.", problem.GetProperty("detail").GetString());
        Assert.False(problem.TryGetProperty("deniedFields", out _));
    }

    [Fact]
    public async Task Refused_fields_are_listed_in_the_body()
    {
        var context = NewHttpContext();

        var handled = await new AccessDeniedExceptionHandler().TryHandleAsync(
            context,
            new AccessDeniedException("Not allowed to set: Price.", ["Price"]),
            CancellationToken.None);

        Assert.True(handled);

        var problem = await ReadBody(context);

        Assert.Equal(["Price"], problem.GetProperty("deniedFields").EnumerateArray().Select(f => f.GetString()));
    }

    [Fact]
    public async Task Any_other_exception_is_left_alone()
    {
        var context = NewHttpContext();

        var handled = await new AccessDeniedExceptionHandler().TryHandleAsync(
            context, new InvalidOperationException("something else"), CancellationToken.None);

        Assert.False(handled);
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
    }

    private static DefaultHttpContext NewHttpContext()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();

        return new DefaultHttpContext
        {
            RequestServices = services.BuildServiceProvider(),
            Response = { Body = new MemoryStream() }
        };
    }

    private static async Task<JsonElement> ReadBody(HttpContext context)
    {
        context.Response.Body.Position = 0;

        using var document = await JsonDocument.ParseAsync(context.Response.Body);

        return document.RootElement.Clone();
    }
}
