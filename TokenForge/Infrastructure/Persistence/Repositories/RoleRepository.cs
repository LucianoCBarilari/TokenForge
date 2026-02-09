using Microsoft.EntityFrameworkCore;
using TokenForge.Domain.Entities;
using TokenForge.Domain.Interfaces;
using TokenForge.Infrastructure.Persistence.DataAccess;
using System;

namespace TokenForge.Infrastructure.Persistence.Repositories
{
    public class RoleRepository(
        TokenForgeContext securityContext
        ) : IRoleRepository
    {
        private readonly TokenForgeContext _context = securityContext;

        public async Task<List<Role>> GetAllAsync() 
        {
            return await _context.Roles.ToListAsync();
        }
        public async Task<Role?> GetByIdAsync(Guid roleId) 
        {
            return await _context.Roles.FindAsync(roleId);
        }
        public async Task AddAsync(Role newRole) 
        {
            await _context.Roles.AddAsync(newRole);
        }
        public async Task UpdateAsync(Role updatedRole) 
        {
            _context.Roles.Update(updatedRole);
        }
        public async Task<List<Role>> GetAllByIdAsync(List<Guid> rolesIds)
        {
            return await _context.Roles
                                 .Where(role => rolesIds.Contains(role.RolesId))
                                 .ToListAsync();
        }
        public async Task<int> SaveChangesAsync()
        {
            return await _context.SaveChangesAsync();
        }
    }
}


