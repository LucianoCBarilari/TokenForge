using Application.Feature.AuthFeature.AuthDto;

namespace Application.Feature.AuthFeature;

public interface IAuthService
{
    Task<Result<AuthResponse>> LoginAsync(User UserLogin);    
    Task<Result> LogoutAsync(Guid UserId, string RToken);
}


