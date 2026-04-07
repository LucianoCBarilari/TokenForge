
using Application.Constants;
using Application.Feature.AuthFeature;
using Application.Feature.AuthFeature.AuthDto;
using Application.Feature.RefreshTokenFeature;
using Application.Feature.TokenFeature;
using Domain.Entities;
using Domain.Errors;
using Domain.Shared;
using Infrastructure.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using System.Security.Claims;
using Web.Security;

namespace Web.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController(
    IAuthService authService,
    IHandleRefreshToken handleRefreshToken,
    ITokenService tokenService,
    AuthCookieWriter authCookieWriter,
    ILogger<AuthController> logger) : ApiControllerBase
{
    private const string AccessTokenCookieName = "accessToken";
    private const string RefreshTokenCookieName = "refreshToken";

    [AllowAnonymous]
    [EnableRateLimiting("login")]
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] UserLoginRequest userLogin)
    {
        if (userLogin == null || string.IsNullOrEmpty(userLogin.UserAccount) || string.IsNullOrEmpty(userLogin.Password))
        {
            logger.LogWarning("Invalid login request: Missing user account or password.");
            return HandleFailure(Result.Failure(AuthErrors.InvalidLoginRequest));
        }

        var user = new User
        {
            UserAccount = userLogin.UserAccount.Trim(),
            PasswordHash = userLogin.Password.Trim()
        };
        Result<AuthResponse> authResult = await authService.LoginAsync(user);

        if (authResult.IsFailure)
        {
            logger.LogWarning("Login failed for user {UserAccount}: {Error}", userLogin.UserAccount, authResult.Error.Message);
            return HandleFailure(authResult);
        }

        AuthResponse successfulAuth = authResult.Value;
        
        var accessTokenCookieOptions = authCookieWriter.BuildAccessTokenCookieOptions();
        Response.Cookies.Append(AccessTokenCookieName, successfulAuth.AccessToken, accessTokenCookieOptions);    
        var refreshTokenCookieOptions = authCookieWriter.BuildRefreshTokenCookieOptions();
        Response.Cookies.Append(RefreshTokenCookieName, successfulAuth.RefreshToken, refreshTokenCookieOptions);
        
        return Ok(new
        {
            userId = successfulAuth.UserId,
            userAccount = successfulAuth.UserAccount,
            tokenType = successfulAuth.TokenType,
            message = "Login successful."
        });
    }

    [Authorize]
    [Authorize(Policy = PermissionCodes.AuthLogout)]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout([FromBody] LogoutRequest? logoutRequest)
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userIdClaim == null || !Guid.TryParse(userIdClaim, out Guid userId))
        {
            logger.LogWarning("Logout attempt failed: User not authenticated or UserId claim missing.");
            return HandleFailure(Result.Failure(AuthErrors.UserNotAuthenticated));
        }
        var refreshToken = logoutRequest?.RefreshToken;
        if (string.IsNullOrWhiteSpace(refreshToken))
            refreshToken = Request.Headers["refreshToken"].FirstOrDefault() ?? Request.Cookies[RefreshTokenCookieName];

        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            logger.LogWarning("Logout failed for user {UserId}: Missing refresh token in body, header or cookie.", userId);
            return HandleFailure(Result.Failure(AuthErrors.MissingRefreshToken));
        }

        var result = await authService.LogoutAsync(userId, refreshToken);

        if (result.IsFailure)
        {
            logger.LogWarning("Logout failed for user {UserId}: {Error}", userId, result.Error.Message);
            return HandleFailure(result);
        }
        Response.Cookies.Delete(AccessTokenCookieName);
        Response.Cookies.Delete(RefreshTokenCookieName);
        return Ok(new { message = "Logout successful" });
    }  

    [AllowAnonymous]
    [EnableRateLimiting("refresh")]
    [HttpPost("tokens/refresh")]
    public async Task<IActionResult> RefreshAccessToken()
    {
        var ct = HttpContext.RequestAborted;
        string refreshToken = Request.Headers["refreshToken"].FirstOrDefault() ?? 
                              Request.Cookies[RefreshTokenCookieName] ?? string.Empty;

        if (string.IsNullOrEmpty(refreshToken))
        {
            logger.LogWarning("Refresh token request failed: Missing refresh token in header or cookie.");
            return HandleFailure(Result.Failure(AuthErrors.MissingRefreshToken));
        }

        var validationResult = await handleRefreshToken.ValidateRefreshToken(refreshToken, ct);
        if (validationResult.IsFailure)
        {
            logger.LogWarning("Refresh token validation failed: {Error}", validationResult.Error.Message);
            return HandleFailure(validationResult);
        }

        var userId = validationResult.Value.UserId;
        var rotateResult = await handleRefreshToken.RotateRefreshTokenSecure(userId, refreshToken, ct);
        if (rotateResult.IsFailure)
        {
            logger.LogWarning("Refresh token rotation failed for user {UserId}: {Error}", userId, rotateResult.Error.Message);
            return HandleFailure(rotateResult);
        }

        Result<string> newTokenResult = await tokenService.GenerateNewAccessTokenAsync(userId);

        if (newTokenResult.IsFailure)
        {
            logger.LogWarning("Failed to generate new access token for user {UserId}: {Error}", userId, newTokenResult.Error.Message);
            return HandleFailure(newTokenResult);
        }

        var accessTokenCookieOptions = authCookieWriter.BuildAccessTokenCookieOptions();
        Response.Cookies.Append(AccessTokenCookieName, newTokenResult.Value, accessTokenCookieOptions);

        var refreshTokenCookieOptions = authCookieWriter.BuildRefreshTokenCookieOptions();
        Response.Cookies.Append(RefreshTokenCookieName, rotateResult.Value, refreshTokenCookieOptions);

        return Ok(new { message = "Token refreshed successfully." });
    }

    [Authorize]
    [Authorize(Policy = PermissionCodes.TokensRevokeCurrent)]
    [HttpPost("tokens/revoke/current")]
    public async Task<IActionResult> RevokeCurrentRefreshToken([FromBody] RefreshAccessTokenRequest? request)
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userIdClaim == null || !Guid.TryParse(userIdClaim, out Guid userId))
        {
            logger.LogWarning("Revoke current refresh token failed: User not authenticated or UserId claim missing.");
            return HandleFailure(Result.Failure(AuthErrors.UserNotAuthenticated));
        }

        var refreshToken = request?.RefreshToken;
        if (string.IsNullOrWhiteSpace(refreshToken))
            refreshToken = Request.Headers["refreshToken"].FirstOrDefault() ?? Request.Cookies[RefreshTokenCookieName];

        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            logger.LogWarning("Revoke current refresh token failed: Missing refresh token in body, header or cookie.");
            return HandleFailure(Result.Failure(AuthErrors.MissingRefreshToken));
        }

        var result = await handleRefreshToken.RevokeCurrentSession(userId, refreshToken, HttpContext.RequestAborted);
        if (result.IsFailure)
        {
            logger.LogWarning("Revoke current refresh token failed for user {UserId}: {Error}", userId, result.Error.Message);
            return HandleFailure(result);
        }

        Response.Cookies.Delete(RefreshTokenCookieName);
        return Ok(new { message = "Current refresh token revoked successfully." });
    }

    [Authorize]
    [Authorize(Policy = PermissionCodes.TokensRevokeAll)]
    [HttpPost("tokens/revoke/users/{userId:guid}")]
    public async Task<IActionResult> RevokeAllUserRefreshTokens(Guid userId)
    {
        if (userId == Guid.Empty)
        {
            logger.LogWarning("Admin revoke all refresh tokens failed: User ID is required.");
            return HandleFailure(Result.Failure(AuthErrors.UserIdRequired));
        }

        var result = await handleRefreshToken.RevokeAllUserTokens(userId, HttpContext.RequestAborted);
        if (result.IsFailure)
        {
            logger.LogWarning("Admin revoke all refresh tokens failed for user {UserId}: {Error}", userId, result.Error.Message);
            return HandleFailure(result);
        }
        return Ok(new { message = "All refresh tokens revoked successfully for user." });
    }    

}



