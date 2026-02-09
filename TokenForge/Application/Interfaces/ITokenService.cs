using TokenForge.Application.Dtos.RefreshTokenDto;
using TokenForge.Domain.Shared;

namespace TokenForge.Application.Interfaces
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


