using Application.Feature.Authz.AuthDto;

namespace Application.Feature.Authz;

public interface IAuthService
{
    Task<Result<AuthResponse>> LoginAsync(User UserLogin);
    Task<Result<string>> GenerateNewJwtToken(Guid UserId);
    Task<Result> LogoutAsync(Guid UserId, string RToken);
}


