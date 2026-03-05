using Application.Feature.TokenFeature.RefreshTokenDto;

namespace Application.Feature.TokenFeature
{
    public interface ITokenService
    {
        Task<Result<RefreshToken>> ValidateRefreshToken(string rtoken);
        Task<Result> RevokeRefreshTokens(Guid UserId, string NewToken);
        Task<Result> RevokeAllUserTokens(Guid userId);
        Task<Result<string>> CreateTokenAsync(Guid userId);
        Task<Result> RevokeCurrentSession(Guid userId, string refreshToken);
        Task<Result<string>> GenerateNewJwtToken(Guid UserId);
    }
}


