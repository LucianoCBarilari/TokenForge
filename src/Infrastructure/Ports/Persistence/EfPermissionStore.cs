using Application.Abstractions.Persistence;
using Domain.Entities;
using Infrastructure.DataAccess;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Ports.Persistence;

public class EfPermissionStore(TokenForgeContext dbContext) : IPermissionStore
{
    public async Task<Permission?> GetByIdAsync(Guid permissionId, CancellationToken ct = default)
    {
        return await dbContext.Permissions.FirstOrDefaultAsync(p => p.PermissionId == permissionId, ct);
    }

    public async Task<Permission?> GetByCodeAsync(string permissionCode, CancellationToken ct = default)
    {
        return await dbContext.Permissions.FirstOrDefaultAsync(p => p.PermissionCode == permissionCode, ct);
    }

    public async Task<List<Permission>> GetAllAsync(CancellationToken ct = default)
    {
        return await dbContext.Permissions.AsNoTracking().ToListAsync(ct);
    }

    public async Task<List<Permission>> GetActiveAsync(CancellationToken ct = default)
    {
        return await dbContext.Permissions
            .AsNoTracking()
            .Where(p => p.IsActive)
            .ToListAsync(ct);
    }

    public async Task AddAsync(Permission permission, CancellationToken ct = default)
    {
        await dbContext.Permissions.AddAsync(permission, ct);
    }

    public void Update(Permission permission)
    {
        dbContext.Permissions.Update(permission);
    }

    public Task SaveChangesAsync(CancellationToken ct = default)
    {
        return dbContext.SaveChangesAsync(ct);
    }
}
