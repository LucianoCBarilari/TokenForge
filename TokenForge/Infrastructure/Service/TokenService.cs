using Microsoft.Extensions.Logging;
using TokenForge.Application.Dtos.RefreshTokenDto;
using TokenForge.Application.Interfaces;
using TokenForge.Domain.Entities;
using TokenForge.Domain.Interfaces;
using TokenForge.Domain.Shared;
using TokenForge.Domain.Errors;
using System.Security.Cryptography;

namespace TokenForge.Infrastructure.Service
{
    public class TokenService(
        IHelpers helper,
        IRefreshTokenRepository refreshTokenRepository,
        ILogger<TokenService> logger
        ) : ITokenService
    {
        private readonly IHelpers _helper = helper;
        private readonly IRefreshTokenRepository _refreshTokenRepository = refreshTokenRepository;
        private readonly ILogger<TokenService> _logger = logger;

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
                DateTime CurrentDate = _helper.GetServerTimeUtc();
                var refreshToken = await _refreshTokenRepository.GetRefreshToken(RAToken, CurrentDate);

                if (refreshToken == null)
                {
                    return Result.Failure(AuthErrors.InvalidRefreshToken);
                }
                return Result.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating refresh token for user {UserId}", RAToken.UserId);
                return Result.Failure(new Error("Token.ValidationFailed", "An error occurred while validating the refresh token."));
            }
        }

        public async Task<Result> RevokeRefreshTokens(Guid UserId, string NewToken)
        {
            try
            {
                DateTime CurrentDate = _helper.GetServerTimeUtc();
                List<RefreshToken> rtList = await _refreshTokenRepository.GetAllByUserId(UserId, CurrentDate);

                if (rtList.Any())
                {
                    foreach (var refreshToken in rtList)
                    {
                        refreshToken.RevokedAt = _helper.GetServerTimeUtc();
                        refreshToken.ReplacedByToken = NewToken;
                        await _refreshTokenRepository.UpdateAsync(refreshToken);
                    }
                    await _refreshTokenRepository.SaveChangesAsync();
                }
                return Result.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error revoking refresh tokens for user {UserId}", UserId);
                return Result.Failure(new Error("Token.RevokeFailed", "An error occurred while revoking refresh tokens."));
            }
        }

        public async Task<Result> RevokeAllUserTokens(Guid userId)
        {
            try
            {
                List<RefreshToken> userTokens = await _refreshTokenRepository.GetRTByIdAndRevokeStatus(userId);

                if (userTokens.Any())
                {
                    foreach (var token in userTokens)
                    {
                        token.RevokedAt = _helper.GetServerTimeUtc();
                    }

                    await _refreshTokenRepository.UpdateRangeAsync(userTokens);
                    await _refreshTokenRepository.SaveChangesAsync();
                }
                
                return Result.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error revoking all user tokens for user {UserId}", userId);
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
                    CreatedAt = _helper.GetServerTimeUtc(),
                    ExpiresAt = _helper.GetServerTimeUtc().AddDays(30)
                };

                await _refreshTokenRepository.AddAsync(newRefreshToken);
                await _refreshTokenRepository.SaveChangesAsync();
                return newToken;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating new token for user {UserId}", userId);
                return new Error("Token.CreationFailed", "An error occurred while creating a new token.");
            }
        }

        public async Task<Result> RevokeCurrentSession(Guid userId, string refreshToken)
        {
            try
            {
                var now = _helper.GetServerTimeUtc();
                var tokens = await _refreshTokenRepository.GetRTByIdAndTokenToRevokeSession(userId, refreshToken);
                
                if (!tokens.Any())
                {
                    return Result.Failure(AuthErrors.InvalidRefreshToken);
                }

                foreach (var token in tokens)
                {
                    token.RevokedAt = now;
                    token.ReplacedByToken = string.Empty;
                }
                await _refreshTokenRepository.UpdateRangeAsync(tokens);
                int result = await _refreshTokenRepository.SaveChangesAsync();

                return result > 0
                    ? Result.Success()
                    : Result.Failure(new Error("Token.RevokeSessionFailed", "Failed to save changes while revoking session."));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error revoking current session for user {UserId}", userId);
                return Result.Failure(new Error("Token.RevokeSessionFailed", "An error occurred while revoking the current session."));
            }
        }
    }
}



