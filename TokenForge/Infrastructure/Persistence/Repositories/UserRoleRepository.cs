using Microsoft.EntityFrameworkCore;
using TokenForge.Application.Dtos.UserRoleDto;
using TokenForge.Domain.Entities;
using TokenForge.Domain.Interfaces;
using TokenForge.Infrastructure.Persistence.DataAccess;

namespace TokenForge.Infrastructure.Persistence.Repositories
{
    public class UserRoleRepository(TokenForgeContext context): IUserRoleRepository
    {
        private readonly TokenForgeContext _context = context;


        public async Task<UserRole?> GetByIdAsync(Guid userRoleId)
        {
            return await _context.UserRoles
                                 .Include(ur => ur.Role)
                                 .FirstOrDefaultAsync(ur => ur.UserRoleId == userRoleId);
        }
        public async Task<List<UserRole>> GetAllAsync()
        {
            var query = @"
                SELECT ur.UserRoleId, ur.UserId, u.UserAccount, ur.RoleId, r.RoleName, ur.AssignedAt, ur.IsActive, ur.DeactivatedAt, ur.DeactivatedReason
                FROM UserRoles AS ur 
                LEFT JOIN Users AS u ON ur.UserId = u.UsersId 
                LEFT JOIN Roles AS r ON ur.RoleId = r.RolesId";
            
            return await _context.Database.SqlQueryRaw<UserRole>(query).ToListAsync();
        }
        public async Task<UserRole?> FindByUserIdAndRoleIdAsync(Guid userId, Guid roleId)
        {
            return await _context.UserRoles
                                 .FirstOrDefaultAsync(ur => ur.UserId == userId && ur.RoleId == roleId);
        }
        public async Task<List<UserRole>> GetRolesByUserIdAsync(Guid userId)
        {
            return await _context.UserRoles
                                 .Where(ur => ur.UserId == userId && ur.IsActive)
                                 .Include(ur => ur.Role)
                                 .ToListAsync();
        }
        public async Task<List<User>> GetUsersByRoleIdAsync(Guid roleId)
        {
            return await _context.UserRoles
                                 .Where(ur => ur.RoleId == roleId && ur.IsActive)
                                 .Include(ur => ur.User)
                                 .Select(ur => ur.User!)
                                 .ToListAsync();
        }
        public async Task<List<UserRole>> GetUserRolesActivesByIdAsync(User user)
        {
            return await _context.UserRoles
                            .Where(ur => ur.UserId == user.UsersId && ur.IsActive)
                            .ToListAsync();
        }

        public async Task AddAsync(UserRole newUserRole)
        {
            await _context.UserRoles.AddAsync(newUserRole);
        }

        public async Task UpdateAsync(UserRole updatedUserRole)
        {
            _context.UserRoles.Update(updatedUserRole);
        }

        public async Task<int> SaveChangesAsync()
        {
            return await _context.SaveChangesAsync();
        }
    }
}


