using Microsoft.EntityFrameworkCore;
using TokenForge.Application.Dtos.RefreshTokenDto;
using TokenForge.Domain.Entities;
using TokenForge.Domain.Interfaces;
using TokenForge.Infrastructure.Persistence.DataAccess;

namespace TokenForge.Infrastructure.Persistence.Repositories
{
    public class RefreshTokenRepository(
        TokenForgeContext context
        ) : IRefreshTokenRepository
    {
        private readonly TokenForgeContext _context = context;

        public async Task<RefreshToken?> GetRefreshToken(RefreshAccessTokenRequest RAToken, DateTime CurrentDate)
        {
            return await _context.RefreshTokens
                    .Where(rt => rt.Token == RAToken.RefreshToken &&
                                 rt.UserId == RAToken.UserId &&
                                 rt.ExpiresAt > CurrentDate &&
                                 rt.RevokedAt == null)
                    .OrderByDescending(rt => rt.ExpiresAt)
                    .FirstOrDefaultAsync();
        }
        public async Task<List<RefreshToken>> GetAllByUserId(Guid UserId,DateTime CurrentDate)
        {
            return await _context.RefreshTokens
                                 .Where(x => x.UserId == UserId && x.ExpiresAt > CurrentDate && x.RevokedAt == null)
                                 .ToListAsync();
        }
        public async Task UpdateAsync(RefreshToken updatedRecord) 
        {
            _context.RefreshTokens.Update(updatedRecord);
        }
        public async Task UpdateRangeAsync(List<RefreshToken> usersToRevokeRT) 
        {
            _context.UpdateRange(usersToRevokeRT);
        }
        public async Task AddAsync(RefreshToken newRecord) 
        {
            await _context.RefreshTokens.AddAsync(newRecord);
        }
        public async Task<List<RefreshToken>> GetRTByIdAndRevokeStatus(Guid userId) 
        {
           return await _context.RefreshTokens
                          .Where(t => t.UserId == userId && t.RevokedAt == null)
                          .ToListAsync();
        }
        public async Task<List<RefreshToken>> GetRTByIdAndTokenToRevokeSession(Guid userId, string LastToken) 
        {
            return await _context.RefreshTokens
                          .Where(rt => rt.UserId == userId && rt.Token == LastToken && rt.RevokedAt == null)
                          .ToListAsync();
        }
        public async Task<int> SaveChangesAsync()
        {
            return await _context.SaveChangesAsync();
        }
    }
}



