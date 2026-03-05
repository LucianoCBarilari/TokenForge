using Application.Abstractions.Common;
using Application.Abstractions.Security;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography;
using System.Text;

namespace Application.Feature.TokenFeature;

// Refresh token security references:
// RFC 6749 §1.5 (refresh token concept)
// https://datatracker.ietf.org/doc/html/rfc6749#section-1.5
// RFC 6819 §5.1.4.2.2 (high-entropy token generation)
// https://datatracker.ietf.org/doc/html/rfc6819#section-5.1.4.2.2
// RFC 6819 §5.2.2.3 and §5.2.2.4 (rotation/revocation)
// https://datatracker.ietf.org/doc/html/rfc6819#section-5.2.2.3
// https://datatracker.ietf.org/doc/html/rfc6819#section-5.2.2.4
// RFC 6819 §5.1.4.1.3 (avoid cleartext token material at rest)
// https://datatracker.ietf.org/doc/html/rfc6819#section-5.1.4.1.3
public class TokenService(
    IUserStore userStore,
    IUserRoleStore userRoleStore,
    IJwtProvider jwtProvider,
    IConfiguration configuration) : ITokenService
{
    private readonly string refreshTokenHashKey = configuration["RefreshTokenSecurity:HashKey"]
        ?? throw new InvalidOperationException("RefreshTokenSecurity:HashKey not found.");

    /*
     * IDE:CA1872
     * https://learn.microsoft.com/es-es/dotnet/fundamentals/code-analysis/quality-rules/ca1872
     */
    public Result<string> GenerateNewRefreshToken()
    {
        var randomNumber = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        string result = Convert.ToHexString(randomNumber);

        return Result<string>.Success(result);
    }

    // Store and query refresh tokens as HMAC-SHA256 hash instead of cleartext.
    public Result<string> HashRefreshToken(string refreshToken)
    {
        if (string.IsNullOrWhiteSpace(refreshToken))
            return Result<string>.Failure(AuthErrors.MissingRefreshToken);

        var keyBytes = Encoding.UTF8.GetBytes(refreshTokenHashKey);
        var tokenBytes = Encoding.UTF8.GetBytes(refreshToken);

        using var hmac = new HMACSHA256(keyBytes);
        var hash = hmac.ComputeHash(tokenBytes);

        return Result<string>.Success(Convert.ToHexString(hash));
    }    
    public async Task<Result<string>> GenerateNewAccessTokenAsync(Guid userId)
    {
        User? user = await userStore.GetByIdAsync(userId);
        
        if (user is null || !user.IsActive)
            return AuthErrors.UserNotFound;

        var roleNames = await userRoleStore.GetActiveRoleNamesByUserIdAsync(user.UsersId);
        if (roleNames.Count == 0)
            return AuthErrors.Unauthorized;

        var newAccessToken = jwtProvider.CreateAccessToken(
            user.UsersId,
            user.Email,
            roleNames);

        return Result<string>.Success(newAccessToken);
    }     
}
