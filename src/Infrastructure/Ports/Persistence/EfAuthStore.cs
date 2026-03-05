using Application.Abstractions.Persistence;
using Domain.Entities;
using Infrastructure.DataAccess;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Ports.Persistence;

public sealed class EfAuthStore(TokenForgeContext dbContext) : IAuthStore
{
    public Task<LoginAttempt?> GetLoginAttemptAsync(string userAccount, CancellationToken ct = default)
    {
        return dbContext.LoginAttempts
            .FirstOrDefaultAsync(x => x.UserAttempt == userAccount, ct);
    }

    public Task AddLoginAttemptAsync(LoginAttempt attempt, CancellationToken ct = default)
    {
        return dbContext.LoginAttempts.AddAsync(attempt, ct).AsTask();
    }

    public void UpdateLoginAttempt(LoginAttempt attempt)
    {
        dbContext.LoginAttempts.Update(attempt);
    }

    public Task<RefreshToken?> GetValidRefreshTokenAsync(        
        string token,
        DateTime nowUtc,
        CancellationToken ct = default)
    {
        return dbContext.RefreshTokens
            .FirstOrDefaultAsync(x => 
                        x.Token == token &&
                        x.ExpiresAt > nowUtc &&
                        x.RevokedAt == null,ct);
    }

    public Task<List<RefreshToken>> GetActiveRefreshTokensAsync(
        Guid userId,
        DateTime nowUtc,
        CancellationToken ct = default)
    {
        return dbContext.RefreshTokens
            .Where(x => x.UserId == userId &&
                        x.ExpiresAt > nowUtc &&
                        x.RevokedAt == null)
            .ToListAsync(ct);
    }

    public Task<RefreshToken?> GetActiveRefreshTokenByValueAsync(
        Guid userId,
        string token,
        CancellationToken ct = default)
    {
        return dbContext.RefreshTokens
            .FirstOrDefaultAsync(x => x.UserId == userId &&
                                      x.Token == token &&
                                      x.RevokedAt == null, ct);
    }

    public Task AddRefreshTokenAsync(RefreshToken token, CancellationToken ct = default)
    {
        return dbContext.RefreshTokens.AddAsync(token, ct).AsTask();
    }

    public void UpdateRefreshToken(RefreshToken token)
    {
        dbContext.RefreshTokens.Update(token);
    }

    public void UpdateRefreshTokens(IEnumerable<RefreshToken> tokens)
    {
        dbContext.RefreshTokens.UpdateRange(tokens);
    }

    public Task SaveChangesAsync(CancellationToken ct = default)
    {
        return dbContext.SaveChangesAsync(ct);
    }
}
