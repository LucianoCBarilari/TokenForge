using Microsoft.EntityFrameworkCore;
using TokenForge.Application.Dtos.UserDto;
using TokenForge.Domain.Entities;
using TokenForge.Domain.Interfaces;
using TokenForge.Infrastructure.Persistence.DataAccess;

namespace TokenForge.Infrastructure.Persistence.Repositories
{
    public class UserRepository(TokenForgeContext context): IUserRepository
    {
        private readonly TokenForgeContext _context = context;

        public async Task AddAsync(User NewUser)
        {
            _context.Users.Add(NewUser);
            // await _context.SaveChangesAsync(); // Removed to centralize SaveChangesAsync call
        }
        public async Task<User?> GetByIdAsync(Guid id)
        {
            return await _context.Users.FindAsync(id);
        }
        public async Task UpdateAsync(User UpdatedUser)
        {
            _context.Users.Update(UpdatedUser);
            // await _context.SaveChangesAsync(); // Removed to centralize SaveChangesAsync call
        }
        public async Task<List<User>> GetAllActiveUsers()
        {
            return await _context.Users.Where(u => u.IsActive).ToListAsync();
        }
        public async Task<List<UserWithRolesResponse>> GetActiveUsersWithRolesAsync()
        {
            return await _context.Users
                .AsNoTracking()
                .Where(u => u.IsActive)
                .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)
                .Select(u => new UserWithRolesResponse
                {
                    UserId = u.UsersId,
                    Email = u.Email,
                    UserAccount = u.UserAccount,
                    IsActive = u.IsActive,
                    Roles = u.UserRoles
                        .Where(ur => ur.IsActive && ur.Role.IsActive)
                        .Select(ur => ur.Role)
                        .ToList()
                }).ToListAsync();
        }
        public async Task<UserWithRolesResponse?> GetActiveUserWithRolesAsync(Guid userId)
        {
            return await _context.Users
                .AsNoTracking()
                .Where(u => u.IsActive && u.UsersId == userId)
                .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)
                .Select(u => new UserWithRolesResponse
                {
                    UserId = u.UsersId,
                    Email = u.Email,
                    UserAccount = u.UserAccount,
                    IsActive = u.IsActive,
                    Roles = u.UserRoles
                        .Where(ur => ur.IsActive && ur.Role.IsActive)
                        .Select(ur => ur.Role)
                        .ToList()
                }).FirstOrDefaultAsync();
        }
        public async Task<bool> GetRegisteredUserAccount(string CurrentAccount) 
        {
           return await _context.Users.AnyAsync(u => u.UserAccount == CurrentAccount);
        }        
        public async Task<bool> GetRegisteredEmail(string CurrentEmail)
        {
            return await _context.Users.AnyAsync(u => u.Email == CurrentEmail);
        }
        public async Task<User?> GetByAccountAsync(string account)
        {
            return await _context.Users
                    .Where(x => x.UserAccount == account)
                    .FirstOrDefaultAsync();
        }
        
        public async Task<int> SaveChangesAsync()
        {
            return await _context.SaveChangesAsync();
        }
    }
}



