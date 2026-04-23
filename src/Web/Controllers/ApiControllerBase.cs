using Domain.Errors;
using Domain.Shared;
using Microsoft.AspNetCore.Mvc;

namespace Web.Controllers;

[ApiController]
[Route("api/[controller]")]
public abstract class ApiControllerBase : ControllerBase
{
    protected IActionResult ToActionResult<T>(Result<T> result)
    {
        if (result.IsSuccess)
            return Ok(result.Value);

        return HandleFailure(result);
    }

    protected IActionResult ToActionResult(Result result)
    {
        if (result.IsSuccess)
            return NoContent();

        return HandleFailure(result);
    }

    protected IActionResult HandleFailure(Result result)
        => HandleFailure(result.Error);

    protected IActionResult HandleFailure(Error error)
    {
        var statusCode = ResolveStatusCode(error);

        return Problem(
            statusCode: statusCode,
            title: ResolveTitle(statusCode),
            detail: error.Message,
            type: ResolveType(statusCode)
        );
    }

    protected IActionResult CreatedResult<T>(string actionName, object routeValues, T data)
        => CreatedAtAction(actionName, routeValues, data);

    protected virtual int ResolveStatusCode(Error error)
    {
        var code = error.Code;

        if (code.EndsWith(".not_found", StringComparison.OrdinalIgnoreCase) ||
            code.EndsWith(".notfound", StringComparison.OrdinalIgnoreCase))
        {
            return StatusCodes.Status404NotFound;
        }

        if (code.Contains("Invalid", StringComparison.OrdinalIgnoreCase) ||
            code.EndsWith(".Required", StringComparison.OrdinalIgnoreCase) ||
            code.EndsWith(".Format", StringComparison.OrdinalIgnoreCase))
        {
            return StatusCodes.Status400BadRequest;
        }

        if (code.Contains("Already", StringComparison.OrdinalIgnoreCase) ||
            code.EndsWith(".InUse", StringComparison.OrdinalIgnoreCase))
        {
            return StatusCodes.Status409Conflict;
        }

        return code switch
        {
            var c when c == AuthErrors.InvalidCredentials.Code => StatusCodes.Status401Unauthorized,
            var c when c == AuthErrors.InvalidLoginRequest.Code => StatusCodes.Status400BadRequest,
            var c when c == AuthErrors.UserLockedOut.Code => StatusCodes.Status401Unauthorized,
            var c when c == AuthErrors.UserNotAuthenticated.Code => StatusCodes.Status401Unauthorized,
            var c when c == AuthErrors.LogoutFailed.Code => StatusCodes.Status400BadRequest,
            var c when c == AuthErrors.MissingRefreshToken.Code => StatusCodes.Status401Unauthorized,
            var c when c == AuthErrors.InvalidRefreshToken.Code => StatusCodes.Status401Unauthorized,
            var c when c == AuthErrors.FailedToGenerateAccessToken.Code => StatusCodes.Status401Unauthorized,
            var c when c == AuthErrors.UserNotFound.Code => StatusCodes.Status404NotFound,
            var c when c == AuthErrors.UserIdRequired.Code => StatusCodes.Status400BadRequest,
            var c when c == AuthErrors.InternalServerError.Code => StatusCodes.Status500InternalServerError,

            var c when c == UserErrors.UserNotFound.Code => StatusCodes.Status404NotFound,
            var c when c == UserErrors.UserAlreadyExists.Code => StatusCodes.Status409Conflict,
            var c when c == UserErrors.EmailAlreadyInUse.Code => StatusCodes.Status409Conflict,
            var c when c == UserErrors.AccountAlreadyInUse.Code => StatusCodes.Status409Conflict,
            var c when c == UserErrors.InvalidPassword.Code => StatusCodes.Status400BadRequest,
            var c when c == UserErrors.PasswordMismatch.Code => StatusCodes.Status400BadRequest,
            var c when c == UserErrors.OldPasswordIncorrect.Code => StatusCodes.Status401Unauthorized,
            var c when c == UserErrors.UserDisabled.Code => StatusCodes.Status401Unauthorized,

            var c when c == RoleErrors.RoleNotFound.Code => StatusCodes.Status404NotFound,

            var c when c == UserRoleErrors.UserNotFound.Code => StatusCodes.Status404NotFound,
            var c when c == UserRoleErrors.RoleNotFound.Code => StatusCodes.Status404NotFound,
            var c when c == UserRoleErrors.UserAlreadyInRole.Code => StatusCodes.Status409Conflict,
            var c when c == UserRoleErrors.ActiveAssignmentNotFound.Code => StatusCodes.Status404NotFound,
            var c when c == UserRoleErrors.UserRoleNotFound.Code => StatusCodes.Status404NotFound,

            var c when c == PermissionErrors.PermissionNotFound.Code => StatusCodes.Status404NotFound,
            var c when c == PermissionErrors.PermissionAlreadyExists.Code => StatusCodes.Status409Conflict,
            var c when c == PermissionErrors.InvalidPermissionCode.Code => StatusCodes.Status400BadRequest,

            var c when c == RolePermissionErrors.RoleNotFound.Code => StatusCodes.Status404NotFound,
            var c when c == RolePermissionErrors.PermissionNotFound.Code => StatusCodes.Status404NotFound,
            var c when c == RolePermissionErrors.RolePermissionAlreadyExists.Code => StatusCodes.Status409Conflict,
            var c when c == RolePermissionErrors.RolePermissionNotFound.Code => StatusCodes.Status404NotFound,

            var c when c == Error.NullValue.Code => StatusCodes.Status400BadRequest,
            _ => StatusCodes.Status500InternalServerError
        };
    }

    private static string ResolveTitle(int statusCode) =>
        statusCode switch
        {
            StatusCodes.Status400BadRequest => "Bad Request",
            StatusCodes.Status401Unauthorized => "Unauthorized",
            StatusCodes.Status404NotFound => "Not Found",
            StatusCodes.Status409Conflict => "Conflict",
            _ => "Internal Server Error"
        };

    private static string ResolveType(int statusCode) =>
        statusCode switch
        {
            StatusCodes.Status400BadRequest => "https://tools.ietf.org/html/rfc7231#section-6.5.1",
            StatusCodes.Status401Unauthorized => "https://tools.ietf.org/html/rfc7235#section-3.1",
            StatusCodes.Status404NotFound => "https://tools.ietf.org/html/rfc7231#section-6.5.4",
            StatusCodes.Status409Conflict => "https://tools.ietf.org/html/rfc7231#section-6.5.8",
            _ => "https://tools.ietf.org/html/rfc7231#section-6.6.1"
        };
}
