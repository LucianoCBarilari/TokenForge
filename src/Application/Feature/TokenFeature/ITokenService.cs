namespace Application.Feature.TokenFeature;

public interface ITokenService
{
    Result<string> GenerateNewRefreshToken();
    Task<Result<string>> GenerateNewAccessTokenAsync(Guid userId);
    Result<string> HashRefreshToken(string refreshToken);
}


