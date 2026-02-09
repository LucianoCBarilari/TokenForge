using TokenForge.Application.Dtos.RefreshTokenDto;
using TokenForge.Domain.Entities;

namespace TokenForge.Domain.Interfaces
{
    public interface IRefreshTokenRepository
    {
        public Task<RefreshToken?> GetRefreshToken(RefreshAccessTokenRequest RAToken, DateTime CurrentDate);
        public Task<List<RefreshToken>> GetAllByUserId(Guid UserId, DateTime CurrentDate);
        public Task<List<RefreshToken>> GetRTByIdAndRevokeStatus(Guid userId);
        public Task UpdateRangeAsync(List<RefreshToken> usersToRevokeRT);
        public Task UpdateAsync(RefreshToken updatedRecord);
        public Task AddAsync(RefreshToken newRecord);
        public Task<List<RefreshToken>> GetRTByIdAndTokenToRevokeSession(Guid userId, string LastToken);
        public Task<int> SaveChangesAsync();
    }
}


