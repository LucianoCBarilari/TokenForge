using Application.Abstractions.Persistence;
using Domain.Entities;
using Infrastructure.DataAccess;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Ports.Persistence;

public class EfAuthStore(TokenForgeContext dbContext) : IAuthStore
{
    public async Task<LoginAttempt?> GetLoginAttemptAsync(string userAccount, CancellationToken ct = default)
    {
        return await dbContext.LoginAttempts
            .FirstOrDefaultAsync(x => x.UserAttempt == userAccount, ct);
    }

    public async Task AddLoginAttemptAsync(LoginAttempt attempt, CancellationToken ct = default)
    {
        await dbContext.LoginAttempts.AddAsync(attempt, ct);
    }

    public void UpdateLoginAttempt(LoginAttempt attempt)
    {
        dbContext.LoginAttempts.Update(attempt);
    }

    public async Task<RefreshToken?> GetValidRefreshTokenAsync(        
        string token,
        DateTime nowUtc,
        CancellationToken ct = default)
    {
        return await dbContext.RefreshTokens
            .FirstOrDefaultAsync(x => 
                        x.Token == token &&
                        x.ExpiresAt > nowUtc &&
                        x.RevokedAt == null,ct);
    }

    public async Task<List<RefreshToken>> GetActiveRefreshTokensAsync(
        Guid userId,
        DateTime nowUtc,
        CancellationToken ct = default)
    {
        return await dbContext.RefreshTokens
            .Where(x => x.UserId == userId &&
                        x.ExpiresAt > nowUtc &&
                        x.RevokedAt == null)
            .ToListAsync(ct);
    }

    public async Task<RefreshToken?> GetActiveRefreshTokenByValueAsync(
        Guid userId,
        string token,
        CancellationToken ct = default)
    {
        return await dbContext.RefreshTokens
            .FirstOrDefaultAsync(x => x.UserId == userId &&
                                      x.Token == token &&
                                      x.RevokedAt == null, ct);
    }

    public async Task AddRefreshTokenAsync(RefreshToken token, CancellationToken ct = default)
    {
        await dbContext.RefreshTokens.AddAsync(token, ct).AsTask();
    }

    public void UpdateRefreshToken(RefreshToken token)
    {
        dbContext.RefreshTokens.Update(token);
    }

    public void UpdateRefreshTokens(IEnumerable<RefreshToken> tokens)
    {
        dbContext.RefreshTokens.UpdateRange(tokens);
    }
    public async  Task<RefreshToken?> FindByIdAndTokenAsync(Guid userId, string tokenHash, CancellationToken ct = default)
    {
        return await dbContext.RefreshTokens
            .FirstOrDefaultAsync(
                rt => rt.UserId == userId && rt.Token == tokenHash,
                ct);
    }

    public Task SaveChangesAsync(CancellationToken ct = default)
    {
        return dbContext.SaveChangesAsync(ct);
    }
}
