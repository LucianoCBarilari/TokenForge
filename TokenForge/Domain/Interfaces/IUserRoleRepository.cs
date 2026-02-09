using TokenForge.Application.Dtos.UserRoleDto;
using TokenForge.Domain.Entities;

namespace TokenForge.Domain.Interfaces
{
    public interface IUserRoleRepository
    {
        public Task AddAsync(UserRole newUserRole);
        public Task UpdateAsync(UserRole updatedUserRole);
        public Task<UserRole?> GetByIdAsync(Guid userRoleId);
        public Task<List<UserRole>> GetAllAsync();
        public Task<UserRole?> FindByUserIdAndRoleIdAsync(Guid userId, Guid roleId);
        public Task<List<UserRole>> GetRolesByUserIdAsync(Guid userId);
        public Task<List<User>> GetUsersByRoleIdAsync(Guid roleId);
        public Task<List<UserRole>> GetUserRolesActivesByIdAsync(User user);
        public Task<int> SaveChangesAsync();
    }
}

