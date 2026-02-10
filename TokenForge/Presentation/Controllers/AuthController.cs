using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TokenForge.Application.Dtos.AuthDto;
using TokenForge.Application.Dtos.RefreshTokenDto;
using TokenForge.Domain.Entities;
using TokenForge.Application.Interfaces;
using TokenForge.Domain.Shared;
using TokenForge.Domain.Errors;
using System.Security.Claims;
using System.Net;
using Microsoft.Extensions.Logging; // Added for ILogger
using Microsoft.AspNetCore.Http;
using TokenForge.WebApi.Models;
using Microsoft.AspNetCore.RateLimiting;

namespace TokenForge.WebApi.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController(IAuthService authService, ITokenService tokenService, ILogger<AuthController> logger) : Controller
    {
        private const string AccessTokenCookieName = "accessToken";
        private const string RefreshTokenCookieName = "refreshToken";

        private readonly IAuthService _authService = authService;
        private readonly ITokenService _tokenService = tokenService;
        private readonly ILogger<AuthController> _logger = logger; // Initialized ILogger

        [AllowAnonymous]
        [EnableRateLimiting("login")]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UserLoginRequest userLogin)
        {
            if (userLogin == null || string.IsNullOrEmpty(userLogin.UserAccount) || string.IsNullOrEmpty(userLogin.Password))
            {
                _logger.LogWarning("Invalid login request: Missing user account or password.");
                return FailResponse(AuthErrors.InvalidLoginRequest, StatusCodes.Status400BadRequest);
            }

            var user = new User
            {
                UserAccount = WebUtility.HtmlEncode(userLogin.UserAccount.Trim()),
                PasswordHash = userLogin.Password.Trim()
            };

            _logger.LogInformation("Attempting login for user {UserAccount}", userLogin.UserAccount);
            Result<AuthResponse> authResult = await _authService.LoginAsync(user);

            if (authResult.IsFailure)
            {
                _logger.LogWarning("Login failed for user {UserAccount}: {Error}", userLogin.UserAccount, authResult.Error.Message);
                return HandleFailure(authResult.Error);
            }

            AuthResponse successfulAuth = authResult.Value;

            if (!string.IsNullOrEmpty(successfulAuth.AccessToken))
            {
                var accessTokenCookieOptions = BuildAccessTokenCookieOptions(successfulAuth.ExpiresIn);
                Response.Cookies.Append(AccessTokenCookieName, successfulAuth.AccessToken, accessTokenCookieOptions);
                _logger.LogInformation("Access token cookie appended for user {UserAccount}", userLogin.UserAccount);
            }

            if (!string.IsNullOrEmpty(successfulAuth.RefreshToken))
            {
                var refreshTokenCookieOptions = BuildRefreshTokenCookieOptions();
                Response.Cookies.Append(RefreshTokenCookieName, successfulAuth.RefreshToken, refreshTokenCookieOptions);
                _logger.LogInformation("Refresh token cookie appended for user {UserAccount}", userLogin.UserAccount);
            }
            
            _logger.LogInformation("Login successful for user {UserAccount}", userLogin.UserAccount);
            return OkResponse(successfulAuth);
        }

        [Authorize]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout([FromBody] LogoutRequest logoutRequest)
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (userIdClaim == null || !Guid.TryParse(userIdClaim, out Guid userId))
            {
                _logger.LogWarning("Logout attempt failed: User not authenticated or UserId claim missing.");
                return FailResponse(AuthErrors.UserNotAuthenticated, StatusCodes.Status401Unauthorized);
            }

            _logger.LogInformation("Attempting logout for user {UserId}", userId);
            var result = await _authService.LogoutAsync(userId, logoutRequest.RefreshToken);

            if (result.IsFailure)
            {
                _logger.LogWarning("Logout failed for user {UserId}: {Error}", userId, result.Error.Message);
                return HandleFailure(result.Error);
            }

            _logger.LogInformation("Logout successful for user {UserId}", userId);
            Response.Cookies.Delete(AccessTokenCookieName);
            Response.Cookies.Delete(RefreshTokenCookieName);
            return OkResponse(message: "Logout successful");
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
                _logger.LogWarning("JWT validation request failed: Access token is missing.");
                return FailResponse(AuthErrors.TokenValidationFailed, StatusCodes.Status400BadRequest);
            }

            try
            {
                var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
                var validationParameters = _authService.GetValidationParameters();

                tokenHandler.ValidateToken(accessToken, validationParameters, out _);
                _logger.LogInformation("JWT validated successfully.");
                return OkResponse(message: "Token is valid.");
            }
            catch (Microsoft.IdentityModel.Tokens.SecurityTokenException ex)
            {
                _logger.LogWarning(ex, "JWT validation failed: {Message}", ex.Message);
                return FailResponse(new Error(AuthErrors.TokenValidationFailed.Code, ex.Message), StatusCodes.Status401Unauthorized);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unexpected error occurred during JWT validation.");
                return FailResponse(AuthErrors.InternalServerError, StatusCodes.Status500InternalServerError);
            }
        }

        [AllowAnonymous]
        [EnableRateLimiting("refresh")]
        [HttpPost("tokens/refresh")]
        public async Task<IActionResult> RefreshAccessToken([FromBody] RefreshAccessTokenRequest refreshAccessTokenRequest)
        {
            string? refreshToken = Request.Headers["refreshToken"].FirstOrDefault() ?? Request.Cookies[RefreshTokenCookieName];

            if (string.IsNullOrEmpty(refreshToken))
            {
                _logger.LogWarning("Refresh token request failed: Missing refresh token in header or cookie.");
                return FailResponse(AuthErrors.MissingRefreshToken, StatusCodes.Status401Unauthorized);
            }

            _logger.LogInformation("Attempting to refresh access token for user {UserId}", refreshAccessTokenRequest.UserId);

            var refreshTokenReq = new RefreshAccessTokenRequest
            {
                UserId = refreshAccessTokenRequest.UserId,
                RefreshToken = refreshToken
            };

            var validationResult = await _tokenService.ValidateRefreshToken(refreshTokenReq);
            if (validationResult.IsFailure)
            {
                _logger.LogWarning("Refresh token validation failed for user {UserId}: {Error}", refreshAccessTokenRequest.UserId, validationResult.Error.Message);
                return HandleFailure(validationResult.Error);
            }

            Result<string> newTokenResult = await _authService.GenerateNewJwtToken(refreshAccessTokenRequest.UserId);

            if (newTokenResult.IsFailure)
            {
                _logger.LogWarning("Failed to generate new access token for user {UserId}: {Error}", refreshAccessTokenRequest.UserId, newTokenResult.Error.Message);
                return HandleFailure(newTokenResult.Error);
            }

            _logger.LogInformation("Access token refreshed successfully for user {UserId}", refreshAccessTokenRequest.UserId);
            var accessTokenCookieOptions = BuildAccessTokenCookieOptions();
            Response.Cookies.Append(AccessTokenCookieName, newTokenResult.Value, accessTokenCookieOptions);
            return OkResponse(new { accessToken = newTokenResult.Value });
        }

        [Authorize]
        [HttpPost("tokens/revoke")]
        public async Task<IActionResult> RevokeRefreshToken([FromBody] RefreshAccessTokenRequest refreshAccessTokenRequest)
        {
            if (refreshAccessTokenRequest.UserId == Guid.Empty)
            {
                _logger.LogWarning("Revoke refresh token request failed: User ID is required.");
                return FailResponse(AuthErrors.UserIdRequired, StatusCodes.Status400BadRequest);
            }
            
            _logger.LogInformation("Attempting to revoke all refresh tokens for user {UserId}", refreshAccessTokenRequest.UserId);
            var result = await _tokenService.RevokeAllUserTokens(refreshAccessTokenRequest.UserId);
            if (result.IsFailure)
            {
                _logger.LogWarning("Revoking all refresh tokens failed for user {UserId}: {Error}", refreshAccessTokenRequest.UserId, result.Error.Message);
                return HandleFailure(result.Error);
            }
            
            _logger.LogInformation("All refresh tokens revoked successfully for user {UserId}", refreshAccessTokenRequest.UserId);
            Response.Cookies.Delete(AccessTokenCookieName);
            Response.Cookies.Delete(RefreshTokenCookieName);
            return OkResponse(message: "Refresh token revoked successfully.");
        }

        private static CookieOptions BuildAccessTokenCookieOptions(int? expiresInSeconds = null)
        {
            var expires = expiresInSeconds.HasValue && expiresInSeconds.Value > 0
                ? DateTime.UtcNow.AddSeconds(expiresInSeconds.Value)
                : DateTime.UtcNow.AddMinutes(30);

            return new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = expires
            };
        }

        private static CookieOptions BuildRefreshTokenCookieOptions()
        {
            return new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(30)
            };
        }

        private IActionResult HandleFailure(Error error)
        {
            return error switch
            {
                { Code: var code } when code == AuthErrors.InvalidCredentials.Code => FailResponse(error, StatusCodes.Status401Unauthorized),
                { Code: var code } when code == AuthErrors.InvalidLoginRequest.Code => FailResponse(error, StatusCodes.Status400BadRequest),
                { Code: var code } when code == AuthErrors.UserLockedOut.Code => FailResponse(error, StatusCodes.Status401Unauthorized), // Consider 423 Locked
                { Code: var code } when code == AuthErrors.UserNotAuthenticated.Code => FailResponse(error, StatusCodes.Status401Unauthorized),
                { Code: var code } when code == AuthErrors.LogoutFailed.Code => FailResponse(error, StatusCodes.Status400BadRequest),
                { Code: var code } when code == AuthErrors.TokenValidationFailed.Code => FailResponse(error, StatusCodes.Status401Unauthorized),
                { Code: var code } when code == AuthErrors.MissingRefreshToken.Code => FailResponse(error, StatusCodes.Status401Unauthorized),
                { Code: var code } when code == AuthErrors.InvalidRefreshToken.Code => FailResponse(error, StatusCodes.Status401Unauthorized),
                { Code: var code } when code == AuthErrors.FailedToGenerateAccessToken.Code => FailResponse(error, StatusCodes.Status401Unauthorized),
                { Code: var code } when code == AuthErrors.UserNotFound.Code => FailResponse(error, StatusCodes.Status404NotFound),
                _ => FailResponse(error, StatusCodes.Status500InternalServerError)
            };
        }

        private IActionResult OkResponse(object? result = null, string? message = null, int statusCode = StatusCodes.Status200OK)
        {
            var response = ApiResponse.SuccessResponse(result, message, statusCode, HttpContext?.TraceIdentifier);
            return StatusCode(statusCode, response);
        }

        private IActionResult FailResponse(Error error, int statusCode, string? message = null)
        {
            var response = ApiResponse.FailureResponse(new[] { error }, message ?? error.Message, statusCode, HttpContext?.TraceIdentifier);
            return StatusCode(statusCode, response);
        }
    }
}



