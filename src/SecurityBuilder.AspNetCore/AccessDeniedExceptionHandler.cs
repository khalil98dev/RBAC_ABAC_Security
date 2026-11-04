using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;

namespace SecurityBuilder.AspNetCore;

/// <summary>
/// Turns an <see cref="AccessDeniedException"/> into 403 with a ProblemDetails body. When fields were
/// refused (R6, R11) they are listed under <c>deniedFields</c>, which is what the caller needs to fix
/// the request. Any other exception is left to the next handler.
/// </summary>
public sealed class AccessDeniedExceptionHandler : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext,
        Exception exception,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        if (exception is not AccessDeniedException denied)
            return false;

        var extensions = denied.DeniedFields.Count > 0
            ? new Dictionary<string, object?> { ["deniedFields"] = denied.DeniedFields }
            : null;

        var problem = Results.Problem(
            detail: denied.Message,
            statusCode: StatusCodes.Status403Forbidden,
            title: "Forbidden",
            extensions: extensions);

        await problem.ExecuteAsync(httpContext);

        return true;
    }
}
