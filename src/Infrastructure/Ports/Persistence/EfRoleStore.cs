using Application.Abstractions.Persistence;
using Domain.Entities;
using Infrastructure.DataAccess;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Ports.Persistence;

public class EfRoleStore(TokenForgeContext dbContext) : IRoleStore
{
    public async Task<Role?> GetByIdAsync(Guid roleId, CancellationToken ct = default)
    {
        return await dbContext.Roles.FirstOrDefaultAsync(x => x.RolesId == roleId, ct);
    }

    public async Task<List<Role>> GetAllAsync(CancellationToken ct = default)
    {
        return await dbContext.Roles.AsNoTracking().ToListAsync(ct);
    }

    public async Task<List<Role>> GetByIdsAsync(IEnumerable<Guid> roleIds, CancellationToken ct = default)
    {
        var ids = roleIds.Distinct().ToList();
        return await dbContext.Roles
            .AsNoTracking()
            .Where(x => ids.Contains(x.RolesId))
            .ToListAsync(ct);
    }

    public void Update(Role role)
    {
        dbContext.Roles.Update(role);
    }

    public Task SaveChangesAsync(CancellationToken ct = default)
    {
        return dbContext.SaveChangesAsync(ct);
    }
}
