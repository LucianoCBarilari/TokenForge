using Application.Abstractions.Persistence;
using Domain.Entities;
using Infrastructure.DataAccess;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Ports.Persistence;

public sealed class EfRolePermissionStore(TokenForgeContext dbContext) : IRolePermissionStore
{
    public Task<RolePermission?> GetAsync(Guid roleId, Guid permissionId, CancellationToken ct = default)
    {
        return dbContext.RolePermissions
            .FirstOrDefaultAsync(rp => rp.RoleId == roleId && rp.PermissionId == permissionId, ct);
    }

    public Task<List<RolePermission>> GetActiveByRoleIdAsync(Guid roleId, CancellationToken ct = default)
    {
        return dbContext.RolePermissions
            .AsNoTracking()
            .Include(rp => rp.Role)
            .Include(rp => rp.Permission)
            .Where(rp => rp.RoleId == roleId && rp.IsActive)
            .ToListAsync(ct);
    }

    public Task<List<RolePermission>> GetActiveByPermissionIdAsync(Guid permissionId, CancellationToken ct = default)
    {
        return dbContext.RolePermissions
            .AsNoTracking()
            .Include(rp => rp.Role)
            .Include(rp => rp.Permission)
            .Where(rp => rp.PermissionId == permissionId && rp.IsActive)
            .ToListAsync(ct);
    }

    public Task<List<Guid>> GetActivePermissionIdsByRoleIdAsync(Guid roleId, CancellationToken ct = default)
    {
        return dbContext.RolePermissions
            .AsNoTracking()
            .Where(rp => rp.RoleId == roleId && rp.IsActive)
            .Select(rp => rp.PermissionId)
            .Distinct()
            .ToListAsync(ct);
    }

    public Task AddAsync(RolePermission rolePermission, CancellationToken ct = default)
    {
        return dbContext.RolePermissions.AddAsync(rolePermission, ct).AsTask();
    }

    public Task AddRangeAsync(IEnumerable<RolePermission> rolePermissions, CancellationToken ct = default)
    {
        return dbContext.RolePermissions.AddRangeAsync(rolePermissions, ct);
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
