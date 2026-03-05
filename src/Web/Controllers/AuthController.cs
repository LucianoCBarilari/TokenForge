using Application.Feature.Authz;
using Application.Feature.Authz.AuthDto;
using Application.Feature.TokenFeature;
using Application.Feature.TokenFeature.RefreshTokenDto;
using Domain.Entities;
using Domain.Errors;
using Domain.Shared;
using Infrastructure.Ports.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using System.Net;
using System.Security.Claims;
using Web.Security;

namespace Web.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController(
    IAuthService authService,
    ITokenService tokenService,
    IJwtValidationParametersProvider jwtValidationParametersProvider,
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
        
        var loginResponse = LoginResponse.FromAuth(successfulAuth);
        return Ok(loginResponse);
    }

    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout([FromBody] LogoutRequest logoutRequest)
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userIdClaim == null || !Guid.TryParse(userIdClaim, out Guid userId))
        {
            logger.LogWarning("Logout attempt failed: User not authenticated or UserId claim missing.");
            return HandleFailure(Result.Failure(AuthErrors.UserNotAuthenticated));
        }


        var result = await authService.LogoutAsync(userId, logoutRequest.RefreshToken);

        if (result.IsFailure)
        {
            logger.LogWarning("Logout failed for user {UserId}: {Error}", userId, result.Error.Message);
            return HandleFailure(result);
        }
        Response.Cookies.Delete(AccessTokenCookieName);
        Response.Cookies.Delete(RefreshTokenCookieName);
        return Ok(new { message = "Logout successful" });
    }

    [Authorize]
    [HttpPost("tokens/validate")]
    public async Task<IActionResult> ValidateJwt([FromBody] AccessTokenRequest accessTokenRequest)
    {
        var accessToken = accessTokenRequest.AccessToken;
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            accessToken = Request.Cookies[AccessTokenCookieName];
        }

        if (string.IsNullOrWhiteSpace(accessToken))
        {
            logger.LogWarning("JWT validation request failed: Access token is missing.");
            return BadRequest(new ProblemDetails
            {
                Title = "Bad Request",
                Detail = AuthErrors.TokenValidationFailed.Message,
                Type = "https://tools.ietf.org/html/rfc7231#section-6.5.1",
                Status = StatusCodes.Status400BadRequest
            });
        }

        try
        {
            var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            var validationParameters = jwtValidationParametersProvider.GetValidationParameters();

            tokenHandler.ValidateToken(accessToken, validationParameters, out _);
            logger.LogInformation("JWT validated successfully.");
            return Ok(new { message = "Token is valid." });
        }
        catch (Microsoft.IdentityModel.Tokens.SecurityTokenException ex)
        {
            logger.LogWarning(ex, "JWT validation failed: {Message}", ex.Message);
            return HandleFailure(Result.Failure(new Error(AuthErrors.TokenValidationFailed.Code, ex.Message)));
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "An unexpected error occurred during JWT validation.");
            return HandleFailure(Result.Failure(AuthErrors.InternalServerError));
        }
    }

    [AllowAnonymous]
    [EnableRateLimiting("refresh")]
    [HttpPost("tokens/refresh")]
    public async Task<IActionResult> RefreshAccessToken()
    {
        string refreshToken = Request.Headers["refreshToken"].FirstOrDefault() ?? 
                              Request.Cookies[RefreshTokenCookieName] ?? string.Empty;

        if (string.IsNullOrEmpty(refreshToken))
        {
            logger.LogWarning("Refresh token request failed: Missing refresh token in header or cookie.");
            return HandleFailure(Result.Failure(AuthErrors.MissingRefreshToken));
        }

        var validationResult = await tokenService.ValidateRefreshToken(refreshToken);
        if (validationResult.IsFailure)
        {
            logger.LogWarning("Refresh token validation failed: {Error}", validationResult.Error.Message);
            return HandleFailure(validationResult);
        }

        Result<string> newTokenResult = await tokenService.GenerateNewJwtToken(validationResult.Value.UserId);

        if (newTokenResult.IsFailure)
        {
            logger.LogWarning("Failed to generate new access token for user {UserId}: {Error}", validationResult.Value.UserId, newTokenResult.Error.Message);
            return HandleFailure(newTokenResult);
        }
        var accessTokenCookieOptions = authCookieWriter.BuildAccessTokenCookieOptions();
        Response.Cookies.Append(AccessTokenCookieName, newTokenResult.Value, accessTokenCookieOptions);
        return Ok(new { accessToken = newTokenResult.Value });
    }

    [Authorize]
    [HttpPost("tokens/revoke")]
    public async Task<IActionResult> RevokeRefreshToken([FromBody] RefreshAccessTokenRequest refreshAccessTokenRequest)
    {
        if (refreshAccessTokenRequest.UserId == Guid.Empty)
        {
            logger.LogWarning("Revoke refresh token request failed: User ID is required.");
            return HandleFailure(Result.Failure(AuthErrors.UserIdRequired));
        }
        var result = await tokenService.RevokeAllUserTokens(refreshAccessTokenRequest.UserId);
        if (result.IsFailure)
        {
            logger.LogWarning("Revoking all refresh tokens failed for user {UserId}: {Error}", refreshAccessTokenRequest.UserId, result.Error.Message);
            return HandleFailure(result);
        }
        Response.Cookies.Delete(AccessTokenCookieName);
        Response.Cookies.Delete(RefreshTokenCookieName);
        return Ok(new { message = "Refresh token revoked successfully." });
    }    

}



