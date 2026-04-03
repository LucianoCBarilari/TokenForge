using Application.Abstractions.Persistence;
using Domain.Entities;
using Infrastructure.DataAccess;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Ports.Persistence;

public class EfRolePermissionStore(TokenForgeContext dbContext) : IRolePermissionStore
{
    public async Task<RolePermission?> GetAsync(Guid roleId, Guid permissionId, CancellationToken ct = default)
    {
        return await dbContext.RolePermissions
            .FirstOrDefaultAsync(rp => rp.RoleId == roleId && rp.PermissionId == permissionId, ct);
    }

    public async Task<List<RolePermission>> GetActiveByRoleIdAsync(Guid roleId, CancellationToken ct = default)
    {
        return await dbContext.RolePermissions
            .AsNoTracking()
            .Include(rp => rp.Role)
            .Include(rp => rp.Permission)
            .Where(rp => rp.RoleId == roleId && rp.IsActive)
            .ToListAsync(ct);
    }

    public async Task<List<RolePermission>> GetActiveByPermissionIdAsync(Guid permissionId, CancellationToken ct = default)
    {
        return await dbContext.RolePermissions
            .AsNoTracking()
            .Include(rp => rp.Role)
            .Include(rp => rp.Permission)
            .Where(rp => rp.PermissionId == permissionId && rp.IsActive)
            .ToListAsync(ct);
    }

    public async Task<List<Guid>> GetActivePermissionIdsByRoleIdAsync(Guid roleId, CancellationToken ct = default)
    {
        return await dbContext.RolePermissions
            .AsNoTracking()
            .Where(rp => rp.RoleId == roleId && rp.IsActive)
            .Select(rp => rp.PermissionId)
            .Distinct()
            .ToListAsync(ct);
    }
    public async Task<List<string>> GetActivePermissionCodesByRoleIdsAsync(
        List<Guid> roleIds,
        CancellationToken ct = default)
    {
        if (roleIds.Count ==0)
            return new List<string>();
        
        return await dbContext.RolePermissions
                .AsNoTracking()
                .Include(rp => rp.Permission)
                .Where(rp => roleIds.Contains(rp.RoleId) && rp.IsActive)
                .Select(rp => rp.Permission.PermissionCode)
                .Distinct()
                .ToListAsync(ct);
    }

    public async Task AddAsync(RolePermission rolePermission, CancellationToken ct = default)
    {
        await dbContext.RolePermissions.AddAsync(rolePermission, ct);
    }

    public async Task AddRangeAsync(IEnumerable<RolePermission> rolePermissions, CancellationToken ct = default)
    {
        await dbContext.RolePermissions.AddRangeAsync(rolePermissions, ct);
    }

    public void Update(RolePermission rolePermission)
    {
        dbContext.RolePermissions.Update(rolePermission);
    }
    public void UpdateRange(IEnumerable<RolePermission> rolePermissions)
    {
        dbContext.RolePermissions.UpdateRange(rolePermissions);
    }
    public Task SaveChangesAsync(CancellationToken ct = default)
    {
        return dbContext.SaveChangesAsync(ct);
    }
}
