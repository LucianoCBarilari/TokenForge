using Application.Abstractions.Persistence;
using Domain.Entities;
using Infrastructure.DataAccess;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Ports.Persistence;

public sealed class EfPermissionStore(TokenForgeContext dbContext) : IPermissionStore
{
    public Task<Permission?> GetByIdAsync(Guid permissionId, CancellationToken ct = default)
    {
        return dbContext.Permissions.FirstOrDefaultAsync(p => p.PermissionId == permissionId, ct);
    }

    public Task<Permission?> GetByCodeAsync(string permissionCode, CancellationToken ct = default)
    {
        return dbContext.Permissions.FirstOrDefaultAsync(p => p.PermissionCode == permissionCode, ct);
    }

    public Task<List<Permission>> GetAllAsync(CancellationToken ct = default)
    {
        return dbContext.Permissions.AsNoTracking().ToListAsync(ct);
    }

    public Task<List<Permission>> GetActiveAsync(CancellationToken ct = default)
    {
        return dbContext.Permissions
            .AsNoTracking()
            .Where(p => p.IsActive)
            .ToListAsync(ct);
    }

    public Task AddAsync(Permission permission, CancellationToken ct = default)
    {
        return dbContext.Permissions.AddAsync(permission, ct).AsTask();
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
