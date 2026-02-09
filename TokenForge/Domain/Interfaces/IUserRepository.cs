using TokenForge.Application.Dtos.UserDto;
using TokenForge.Domain.Entities;

namespace TokenForge.Domain.Interfaces
{
    public interface IUserRepository
    {
        public Task AddAsync(User newUser);
        public Task<User?> GetByIdAsync(Guid id);
        public Task<User?> GetByAccountAsync(string account);
        public Task UpdateAsync(User updatedUser);
        public Task<List<User>> GetAllActiveUsers();
        public Task<List<UserWithRolesResponse>> GetActiveUsersWithRolesAsync();
        public Task<UserWithRolesResponse?> GetActiveUserWithRolesAsync(Guid userId);
        public Task<bool> GetRegisteredUserAccount(string currentAccount);
        public Task<bool> GetRegisteredEmail(string currentEmail);
        public Task<int> SaveChangesAsync();
    }
}


