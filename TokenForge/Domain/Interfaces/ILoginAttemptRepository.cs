using TokenForge.Domain.Entities;

namespace TokenForge.Domain.Interfaces
{
    public interface ILoginAttemptRepository
    {
        public Task<LoginAttempt?> GetInfoByUserAccount(string userAccount);
        public Task UpdateAsync(LoginAttempt updateRecord);
        public Task<int> SaveChangesAsync();
        public Task AddAsync(LoginAttempt newRecord);
    }
}

