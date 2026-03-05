using Application.Abstractions.Common;
using Application.Feature.TokenFeature;
using Microsoft.Extensions.Configuration;

namespace Application.Feature.RefreshTokenFeature;

public class HandleRefreshToken(
    ITokenService tokenService,
    IAuthStore authStore,
    IConfiguration configuration,
    IClock clock) : IHandleRefreshToken
{
    private readonly int refreshTokenDays = GetRefreshTokenDays(configuration);

    private static int GetRefreshTokenDays(IConfiguration configuration)
    {
        var value = configuration.GetValue<int>("AuthCookie:RefreshTokenDays");
        if (value <= 0)
            throw new InvalidOperationException("AuthCookie:RefreshTokenDays must be greater than 0.");

        return value;
    }

    public async Task<Result<string>> CreateRefreshTokenAsync(Guid userId, CancellationToken ct = default)
    {
        var now = clock.UtcNow;

        var newTokenResult = tokenService.GenerateNewRefreshToken();
        if (newTokenResult.IsFailure)
            return Result<string>.Failure(newTokenResult.Error);

        var newHashResult = tokenService.HashRefreshToken(newTokenResult.Value);
        if (newHashResult.IsFailure)
            return Result<string>.Failure(newHashResult.Error);

        var activeTokens = await authStore.GetActiveRefreshTokensAsync(userId, now, ct);
        foreach (var token in activeTokens)
        {
            token.RevokedAt = now;
            token.ReplacedByToken = newHashResult.Value;
        }

        if (activeTokens.Count > 0)
            authStore.UpdateRefreshTokens(activeTokens);

        var newRefreshToken = new RefreshToken
        {
            UserId = userId,
            Token = newHashResult.Value,
            CreatedAt = now,
            ExpiresAt = now.AddDays(refreshTokenDays)
        };

        await authStore.AddRefreshTokenAsync(newRefreshToken, ct);
        await authStore.SaveChangesAsync(ct);
        return Result<string>.Success(newTokenResult.Value);
    }

    public async Task<Result<RefreshToken>> ValidateRefreshToken(string refreshToken, CancellationToken ct = default)
    {
        var tokenHashResult = tokenService.HashRefreshToken(refreshToken);
        if (tokenHashResult.IsFailure)
            return Result<RefreshToken>.Failure(tokenHashResult.Error);

        var refreshTokenRecord = await authStore.GetValidRefreshTokenAsync(tokenHashResult.Value, clock.UtcNow, ct);
        if (refreshTokenRecord is null)
            return Result<RefreshToken>.Failure(AuthErrors.InvalidRefreshToken);

        return Result<RefreshToken>.Success(refreshTokenRecord);
    }

    public async Task<Result> RevokeRefreshToken(Guid userId, string token, CancellationToken ct = default)
    {
        var tokenHashResult = tokenService.HashRefreshToken(token);
        if (tokenHashResult.IsFailure)
            return Result.Failure(tokenHashResult.Error);

        var now = clock.UtcNow;
        var currentToken = await authStore.GetValidRefreshTokenAsync(tokenHashResult.Value, now, ct);
        if (currentToken is null || currentToken.UserId != userId)
            return Result.Failure(AuthErrors.InvalidRefreshToken);

        currentToken.RevokedAt = now;
        currentToken.ReplacedByToken = null;

        authStore.UpdateRefreshToken(currentToken);
        await authStore.SaveChangesAsync(ct);
        return Result.Success();
    }

    public async Task<Result<string>> RotateRefreshTokenSecure(Guid userId, string currentToken, CancellationToken ct = default)
    {
        var now = clock.UtcNow;

        var currentHashResult = tokenService.HashRefreshToken(currentToken);
        if (currentHashResult.IsFailure)
            return Result<string>.Failure(currentHashResult.Error);

        var tokenRecord = await authStore.FindByIdAndTokenAsync(userId, currentHashResult.Value, ct);
        if (tokenRecord is null)
            return Result<string>.Failure(AuthErrors.InvalidRefreshToken);

       
        if (tokenRecord.RevokedAt is not null)
        {
            await RevokeAllUserTokens(userId, ct);
            return Result<string>.Failure(AuthErrors.InvalidRefreshToken);
        }

        
        if (tokenRecord.ExpiresAt <= now)
            return Result<string>.Failure(AuthErrors.InvalidRefreshToken);

        var newTokenResult = tokenService.GenerateNewRefreshToken();
        if (newTokenResult.IsFailure)
            return Result<string>.Failure(newTokenResult.Error);

        var newHashResult = tokenService.HashRefreshToken(newTokenResult.Value);
        if (newHashResult.IsFailure)
            return Result<string>.Failure(newHashResult.Error);

        tokenRecord.RevokedAt = now;
        tokenRecord.ReplacedByToken = newHashResult.Value;
        authStore.UpdateRefreshToken(tokenRecord);

        var newRefreshToken = new RefreshToken
        {
            UserId = userId,
            Token = newHashResult.Value,
            CreatedAt = now,
            ExpiresAt = now.AddDays(refreshTokenDays)
        };

        await authStore.AddRefreshTokenAsync(newRefreshToken, ct);
        await authStore.SaveChangesAsync(ct);

        return Result<string>.Success(newTokenResult.Value);
    }

    public async Task<Result> RevokeAllUserTokens(Guid userId, CancellationToken ct = default)
    {
        var now = clock.UtcNow;
        var tokens = await authStore.GetActiveRefreshTokensAsync(userId, now, ct);

        if (tokens.Count == 0)
            return Result.Success();

        foreach (var token in tokens)
        {
            token.RevokedAt = now;
            token.ReplacedByToken = null;
        }

        authStore.UpdateRefreshTokens(tokens);
        await authStore.SaveChangesAsync(ct);
        return Result.Success();
    }

    public async Task<Result> RevokeCurrentSession(Guid userId, string refreshToken, CancellationToken ct = default)
    {
        var tokenHashResult = tokenService.HashRefreshToken(refreshToken);
        if (tokenHashResult.IsFailure)
            return Result.Failure(tokenHashResult.Error);

        var token = await authStore.GetActiveRefreshTokenByValueAsync(userId, tokenHashResult.Value, ct);
        if (token is null)
            return Result.Failure(AuthErrors.InvalidRefreshToken);

        token.RevokedAt = clock.UtcNow;
        token.ReplacedByToken = null;

        authStore.UpdateRefreshToken(token);
        await authStore.SaveChangesAsync(ct);
        return Result.Success();
    }
}
