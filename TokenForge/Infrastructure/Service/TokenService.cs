using System.Security.Cryptography;
using TokenForge.Application.Dtos.RefreshTokenDto;
using TokenForge.Domain.Entities;
using TokenForge.Infrastructure.DataAccess;

namespace TokenForge.Infrastructure.Service;
public class TokenService(
    TokenForgeContext _dbContext,
    Helpers helper,
    ILogger<TokenService> logger
    ) : ITokenService
{

    private string GenerateRefreshToken()
    {
        var randomNumber = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return BitConverter.ToString(randomNumber).Replace("-", "");
    }

    public async Task<Result> ValidateRefreshToken(RefreshAccessTokenRequest RAToken)
    {
        try
        {
            DateTime CurrentDate = helper.GetServerTimeUtc();
            var refreshToken = await _dbContext.RefreshTokens
                                                            .Where(rt => rt.Token == RAToken.RefreshToken &&
                                                                         rt.UserId == RAToken.UserId &&
                                                                         rt.ExpiresAt > CurrentDate &&
                                                                         rt.RevokedAt == null)
                                                            .OrderByDescending(rt => rt.ExpiresAt)
                                                            .FirstOrDefaultAsync();
            if (refreshToken == null)
            {
                return Result.Failure(AuthErrors.InvalidRefreshToken);
            }
            return Result.Success();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error validating refresh token for user {UserId}", RAToken.UserId);
            return Result.Failure(new Error("Token.ValidationFailed", "An error occurred while validating the refresh token."));
        }
    }

    public async Task<Result> RevokeRefreshTokens(Guid UserId, string NewToken)
    {
        try
        {
            DateTime CurrentDate = helper.GetServerTimeUtc();
            List<RefreshToken> rtList = await _dbContext.RefreshTokens
                                                                     .Where(x => x.UserId == UserId && x.ExpiresAt > CurrentDate && x.RevokedAt == null)
                                                                     .ToListAsync();
            if (rtList.Any())
            {
                foreach (var refreshToken in rtList)
                {
                    refreshToken.RevokedAt = helper.GetServerTimeUtc();
                    refreshToken.ReplacedByToken = NewToken;
                    _dbContext.Update(refreshToken);
                }
                await _dbContext.SaveChangesAsync();
            }
            return Result.Success();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error revoking refresh tokens for user {UserId}", UserId);
            return Result.Failure(new Error("Token.RevokeFailed", "An error occurred while revoking refresh tokens."));
        }
    }

    public async Task<Result> RevokeAllUserTokens(Guid userId)
    {
        try
        {
            List<RefreshToken> userTokens = await _dbContext.RefreshTokens
                                                                          .Where(t => t.UserId == userId && t.RevokedAt == null)
                                                                          .ToListAsync();

            if (userTokens.Count != 0)
            {
                foreach (var token in userTokens)
                {
                    token.RevokedAt = helper.GetServerTimeUtc();
                }

                _dbContext.UpdateRange(userTokens);
                await _dbContext.SaveChangesAsync();
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
            var newToken = GenerateRefreshToken();
            var revokeResult = await RevokeRefreshTokens(userId, newToken);
            if (revokeResult.IsFailure)
            {
                return revokeResult.Error;
            }

            var newRefreshToken = new RefreshToken
            {
                UserId = userId,
                Token = newToken,
                CreatedAt = helper.GetServerTimeUtc(),
                ExpiresAt = helper.GetServerTimeUtc().AddDays(30)
            };

            await _dbContext.RefreshTokens.AddAsync(newRefreshToken);
            await _dbContext.SaveChangesAsync();
            return newToken;
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
            var now = helper.GetServerTimeUtc();
            var tokens = await _dbContext.RefreshTokens
                                                    .Where(rt => rt.UserId == userId && rt.Token == refreshToken && rt.RevokedAt == null)
                                                    .ToListAsync();

            if (tokens.Count == 0)
            {
                return Result.Failure(AuthErrors.InvalidRefreshToken);
            }

            foreach (var token in tokens)
            {
                token.RevokedAt = now;
                token.ReplacedByToken = string.Empty;
            }
            _dbContext.UpdateRange(tokens);
            int result = await _dbContext.SaveChangesAsync();

            return result > 0
                ? Result.Success()
                : Result.Failure(new Error("Token.RevokeSessionFailed", "Failed to save changes while revoking session."));
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error revoking current session for user {UserId}", userId);
            return Result.Failure(new Error("Token.RevokeSessionFailed", "An error occurred while revoking the current session."));
        }
    }
}