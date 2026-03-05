using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace Web.Exceptions;

public class GlobalExceptionHandler(
        ILogger<GlobalExceptionHandler> logger,
        IProblemDetailsService problemDetailsService,
        IHostEnvironment environment) : IExceptionHandler
{

    public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        logger.LogError(exception,
            "Unhandled exception occurred. TraceId: {TraceId}, Path: {Path}",
            httpContext.TraceIdentifier,
            httpContext.Request.Path);

        int statusCode = StatusCodes.Status500InternalServerError;
        string title = "Internal Server Error";
        string? detail = environment.IsDevelopment() ? exception.Message : null;

        var problemDetails = new ProblemDetails
        {
            Status = statusCode,
            Title = title,
            Detail = detail,
            Instance = $"{httpContext.Request.Method} {httpContext.Request.Path}"
        };

        var pdContext = new ProblemDetailsContext
        {
            HttpContext = httpContext,
            ProblemDetails = problemDetails,
            Exception = exception
        };

        var handled = await problemDetailsService.TryWriteAsync(pdContext);


        if (!handled)
        {
            httpContext.Response.StatusCode = statusCode;
            httpContext.Response.ContentType = "application/problem+json";
            await httpContext.Response.WriteAsJsonAsync(problemDetails, cancellationToken: cancellationToken);
        }


        return true;
    }
}
