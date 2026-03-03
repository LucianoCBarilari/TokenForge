using Application.Feature.TokenFeature.RefreshTokenDto;

namespace Application.Feature.TokenFeature
{
    public interface ITokenService
    {
        Task<Result> ValidateRefreshToken(RefreshAccessTokenRequest RAToken);
        Task<Result> RevokeRefreshTokens(Guid UserId, string NewToken);
        Task<Result> RevokeAllUserTokens(Guid userId);
        Task<Result<string>> CreateTokenAsync(Guid userId);
        Task<Result> RevokeCurrentSession(Guid userId, string refreshToken);
    }
}


