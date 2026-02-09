using TokenForge.Domain.Entities;

namespace TokenForge.Domain.Interfaces
{
    public interface IRoleRepository
    {
        public Task<List<Role>> GetAllAsync();
        public Task<Role?> GetByIdAsync(Guid roleId);
        public Task AddAsync(Role newRole);
        public Task UpdateAsync(Role updatedRole);
        public  Task<List<Role>> GetAllByIdAsync(List<Guid> rolesIds);
        public  Task<int> SaveChangesAsync();
    }
}

