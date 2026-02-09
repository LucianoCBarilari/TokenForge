using Microsoft.IdentityModel.Tokens;
using TokenForge.Application.Dtos.AuthDto;
using TokenForge.Domain.Entities;
using TokenForge.Domain.Shared;

namespace TokenForge.Application.Interfaces
{
    public interface IAuthService
    {
        Task<Result<AuthResponse>> LoginAsync(User UserLogin);
        Task<Result<string>> GenerateNewJwtToken(Guid UserId);
        Task<Result> LogoutAsync(Guid UserId, string RToken);
        TokenValidationParameters GetValidationParameters();
    }
}


