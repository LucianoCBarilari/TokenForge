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
    IAuthStore authStore,
    IUserStore userStore,
    IUserRoleStore userRoleStore,
    IJwtProvider jwtProvider,
    IClock clock,
    IConfiguration configuration,
    ILogger<TokenService> logger) : ITokenService
{
    //Corregir esto no debe ir aqui, se debe configurar desde el appsettings o similar  
    private static readonly TimeSpan RefreshTokenLifetime = TimeSpan.FromDays(30);
    private readonly string _refreshTokenHashKey = configuration["RefreshTokenSecurity:HashKey"]
        ?? throw new InvalidOperationException("RefreshTokenSecurity:HashKey not found.");
    
    /*
     * IDE:CA1872
     * https://learn.microsoft.com/es-es/dotnet/fundamentals/code-analysis/quality-rules/ca1872
     */
    private string GenerateRefreshToken()
    {
        var randomNumber = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToHexString(randomNumber);
    }

    // Store and query refresh tokens as HMAC-SHA256 hash instead of cleartext.
    private string HashRefreshToken(string refreshToken)
    {
        var keyBytes = Encoding.UTF8.GetBytes(_refreshTokenHashKey);
        var tokenBytes = Encoding.UTF8.GetBytes(refreshToken);
        using var hmac = new HMACSHA256(keyBytes);
        var hash = hmac.ComputeHash(tokenBytes);
        return Convert.ToHexString(hash);
    }

    public async Task<Result<RefreshToken>> ValidateRefreshToken(string refreshToken)
    {
        var tokenHash = HashRefreshToken(refreshToken);
        var refreshT = await authStore.GetValidRefreshTokenAsync(tokenHash, clock.UtcNow);

        if (refreshT is null)
        {
            return Result<RefreshToken>.Failure(AuthErrors.InvalidRefreshToken);
        }

        return Result<RefreshToken>.Success(refreshT);
    }
    public async Task<Result<string>> GenerateNewJwtToken(Guid userId)
    {
        var user = await userStore.GetByIdAsync(userId);
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

    public async Task<Result> RevokeRefreshTokens(Guid userId, string newToken)
    {
        var newTokenHash = HashRefreshToken(newToken);
        var now = clock.UtcNow;
        var tokens = await authStore.GetActiveRefreshTokensAsync(userId, now);

        if (tokens.Count != 0)
        {
            foreach (var refreshToken in tokens)
            {
                refreshToken.RevokedAt = now;
                refreshToken.ReplacedByToken = newTokenHash;
            }

            authStore.UpdateRefreshTokens(tokens);
            await authStore.SaveChangesAsync();
        }

        return Result.Success();
    }

    public async Task<Result> RevokeAllUserTokens(Guid userId)
    {
        var now = clock.UtcNow;
        var tokens = await authStore.GetActiveRefreshTokensAsync(userId, now);

        if (tokens.Count != 0)
        {
            foreach (var token in tokens)
            {
                token.RevokedAt = now;
            }

            authStore.UpdateRefreshTokens(tokens);
            await authStore.SaveChangesAsync();
        }

        return Result.Success();
    }

    public async Task<Result<string>> CreateTokenAsync(Guid userId)
    {
        var now = clock.UtcNow;
        var newToken = GenerateRefreshToken();
        var revokeResult = await RevokeRefreshTokens(userId, newToken);
        if (revokeResult.IsFailure)
        {
            return revokeResult.Error;
        }

        var refreshToken = new RefreshToken
        {
            UserId = userId,
            Token = HashRefreshToken(newToken),
            CreatedAt = now,
            ExpiresAt = now.Add(RefreshTokenLifetime)
        };

        await authStore.AddRefreshTokenAsync(refreshToken);
        await authStore.SaveChangesAsync();
        return Result<string>.Success(newToken);       
    }

    public async Task<Result> RevokeCurrentSession(Guid userId, string refreshToken)
    {
        var tokenHash = HashRefreshToken(refreshToken);
        var token = await authStore.GetActiveRefreshTokenByValueAsync(userId, tokenHash);
        if (token is null)
        {
            return Result.Failure(AuthErrors.InvalidRefreshToken);
        }

        token.RevokedAt = clock.UtcNow;
        token.ReplacedByToken = null;

        authStore.UpdateRefreshToken(token);
        await authStore.SaveChangesAsync();
        return Result.Success();
    }
}
