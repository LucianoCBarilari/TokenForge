/*
 *TokenService issues refresh tokens as high-entropy, cryptographically random
 * values for OAuth 2.0 session renewal.
 * RFC 6749 1.5: https://datatracker.ietf.org/doc/html/rfc6749#section-1.5
 * RFC 6819 5.1.4.2.2: https://datatracker.ietf.org/doc/html/rfc6819#section-5.1.4.2.2
 */
using Application.Abstractions.Common;
using Application.Feature.TokenFeature.RefreshTokenDto;
using System.Security.Cryptography;

namespace Application.Feature.TokenFeature;

public class TokenService(
    IAuthStore authStore,
    IClock clock,
    ILogger<TokenService> logger) : ITokenService
{
    //Corregir esto no debe ir aqui, se debe configurar desde el appsettings o similar  
    private static readonly TimeSpan RefreshTokenLifetime = TimeSpan.FromDays(30);


    /*
     *https://datatracker.ietf.org/doc/html/rfc6819#section-5.1.4.2.2 
     *Refresh tokens are generated with cryptographically secure randomness
     *(RFC 6819 5.1.4.2.2) and used as OAuth 2.0 refresh credentials
     *(RFC 6749 1.5).
    */
    /*
     * IDE:CA1872
     * https://learn.microsoft.com/es-es/dotnet/fundamentals/code-analysis/quality-rules/ca1872
     */
    private string GenerateRefreshToken()
    {
        var randomNumber = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToHexString(randomNumber);
    }

    public async Task<Result> ValidateRefreshToken(RefreshAccessTokenRequest request)
    {
        try
        {
            var refreshToken = await authStore.GetValidRefreshTokenAsync(
                request.UserId,
                request.RefreshToken,
                clock.UtcNow);

            if (refreshToken == null)
            {
                return Result.Failure(AuthErrors.InvalidRefreshToken);
            }

            return Result.Success();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error validating refresh token for user {UserId}", request.UserId);
            return Result.Failure(new Error("Token.ValidationFailed", "An error occurred while validating the refresh token."));
        }
    }

    public async Task<Result> RevokeRefreshTokens(Guid userId, string newToken)
    {
        try
        {
            var now = clock.UtcNow;
            var tokens = await authStore.GetActiveRefreshTokensAsync(userId, now);

            if (tokens.Count != 0)
            {
                foreach (var refreshToken in tokens)
                {
                    refreshToken.RevokedAt = now;
                    refreshToken.ReplacedByToken = newToken;
                }

                authStore.UpdateRefreshTokens(tokens);
                await authStore.SaveChangesAsync();
            }

            return Result.Success();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error revoking refresh tokens for user {UserId}", userId);
            return Result.Failure(new Error("Token.RevokeFailed", "An error occurred while revoking refresh tokens."));
        }
    }

    public async Task<Result> RevokeAllUserTokens(Guid userId)
    {
        try
        {
            var now = clock.UtcNow;
            var tokens = await authStore.GetActiveRefreshTokensAsync(userId, now);

            if (tokens.Count != 0)
            {
                foreach (var token in tokens)
                {
                    token.RevokedAt = now;
                }

                authStore.UpdateRefreshTokens(tokens);
                await authStore.SaveChangesAsync();
            }

            return Result.Success();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error revoking all user tokens for user {UserId}", userId);
            return Result.Failure(new Error("Token.RevokeAllFailed", "An error occurred while revoking all user tokens."));
        }
    }

    public async Task<Result<string>> CreateTokenAsync(Guid userId)
    {
        try
        {
            var now = clock.UtcNow;
            var newToken = GenerateRefreshToken();
            var revokeResult = await RevokeRefreshTokens(userId, newToken);
            if (revokeResult.IsFailure)
            {
                return revokeResult.Error;
            }

            var refreshToken = new RefreshToken
            {
                UserId = userId,
                Token = newToken,
                CreatedAt = now,
                ExpiresAt = now.Add(RefreshTokenLifetime)
            };

            await authStore.AddRefreshTokenAsync(refreshToken);
            await authStore.SaveChangesAsync();
            return Result<string>.Success(newToken);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error creating new token for user {UserId}", userId);
            return new Error("Token.CreationFailed", "An error occurred while creating a new token.");
        }
    }

    public async Task<Result> RevokeCurrentSession(Guid userId, string refreshToken)
    {
        try
        {
            var token = await authStore.GetActiveRefreshTokenByValueAsync(userId, refreshToken);
            if (token is null)
            {
                return Result.Failure(AuthErrors.InvalidRefreshToken);
            }

            token.RevokedAt = clock.UtcNow;
            token.ReplacedByToken = null;

            authStore.UpdateRefreshToken(token);
            await authStore.SaveChangesAsync();
            return Result.Success();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error revoking current session for user {UserId}", userId);
            return Result.Failure(new Error("Token.RevokeSessionFailed", "An error occurred while revoking the current session."));
        }
    }
}
