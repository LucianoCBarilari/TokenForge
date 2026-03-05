namespace Application.Feature.RefreshTokenFeature;

public interface IHandleRefreshToken
{
    Task<Result<string>> CreateRefreshTokenAsync(Guid userId, CancellationToken ct = default);
    Task<Result<RefreshToken>> ValidateRefreshToken(string refreshToken, CancellationToken ct = default);
    Task<Result> RevokeRefreshToken(Guid userId, string token, CancellationToken ct = default);
    Task<Result<string>> RotateRefreshTokenSecure(Guid userId, string currentToken, CancellationToken ct = default);
    Task<Result> RevokeAllUserTokens(Guid userId, CancellationToken ct = default);
    Task<Result> RevokeCurrentSession(Guid userId, string refreshToken, CancellationToken ct = default);
}
