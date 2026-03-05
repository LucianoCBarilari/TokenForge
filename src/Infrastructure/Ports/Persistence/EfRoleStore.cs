using Application.Abstractions.Persistence;
using Domain.Entities;
using Infrastructure.DataAccess;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Ports.Persistence;

public sealed class EfRoleStore(TokenForgeContext dbContext) : IRoleStore
{
    public Task<Role?> GetByIdAsync(Guid roleId, CancellationToken ct = default)
    {
        return dbContext.Roles.FirstOrDefaultAsync(x => x.RolesId == roleId, ct);
    }

    public Task<List<Role>> GetAllAsync(CancellationToken ct = default)
    {
        return dbContext.Roles.AsNoTracking().ToListAsync(ct);
    }

    public Task<List<Role>> GetByIdsAsync(IEnumerable<Guid> roleIds, CancellationToken ct = default)
    {
        var ids = roleIds.Distinct().ToList();
        return dbContext.Roles
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
