using Microsoft.EntityFrameworkCore;
using TokenForge.Domain.Entities;
using TokenForge.Domain.Interfaces;
using TokenForge.Infrastructure.Persistence.DataAccess;

namespace TokenForge.Infrastructure.Persistence.Repositories
{
    public class LoginAttemptRepository(
        TokenForgeContext context
        ) : ILoginAttemptRepository
    {
        private readonly TokenForgeContext _context = context;

        public async Task<LoginAttempt?> GetInfoByUserAccount(string userAccount)
        {
            return await _context.LoginAttempts
                                 .Where(x => x.UserAttempt == userAccount)
                                 .FirstOrDefaultAsync();
        }
        public async Task UpdateAsync(LoginAttempt updateRecord) 
        {
            _context.LoginAttempts.Update(updateRecord);
        }
        public async Task AddAsync(LoginAttempt newRecord)
        {
            await _context.LoginAttempts.AddAsync(newRecord);
        }

        public async Task<int> SaveChangesAsync()
        {
            return await _context.SaveChangesAsync();
        }

    }
}


