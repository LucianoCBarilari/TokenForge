namespace Application.Feature.TokenFeature;

public interface ITokenService
{
    Result<string> GenerateNewRefreshToken();
    Task<Result<string>> GenerateNewAccessTokenAsync(Guid userId);
    Task<Result<string>> GenerateNewAccessTokenAsync(Guid userId, string email);
    Result<string> HashRefreshToken(string refreshToken);
}


