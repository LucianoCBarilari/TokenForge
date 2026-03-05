using Application.Abstractions.Persistence;
using Domain.Entities;
using Infrastructure.DataAccess;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Ports.Persistence;

public sealed class EfUserRoleStore(TokenForgeContext dbContext) : IUserRoleStore
{
    public Task<UserRole?> GetAsync(Guid userId, Guid roleId, CancellationToken ct = default)
    {
        return dbContext.UserRoles
            .FirstOrDefaultAsync(x => x.UserId == userId && x.RoleId == roleId, ct);
    }

    public Task<UserRole?> GetByIdAsync(Guid userRoleId, CancellationToken ct = default)
    {
        return dbContext.UserRoles
            .Include(x => x.User)
            .Include(x => x.Role)
            .FirstOrDefaultAsync(x => x.UserRoleId == userRoleId, ct);
    }

    public Task<List<UserRole>> GetActiveByUserIdAsync(Guid userId, CancellationToken ct = default)
    {
        return dbContext.UserRoles
            .AsNoTracking()
            .Include(x => x.Role)
            .Where(x => x.UserId == userId && x.IsActive)
            .ToListAsync(ct);
    }

    public Task<List<User>> GetActiveUsersByRoleIdAsync(Guid roleId, CancellationToken ct = default)
    {
        return dbContext.UserRoles
            .AsNoTracking()
            .Where(x => x.RoleId == roleId && x.IsActive)
            .Include(x => x.User)
            .Select(x => x.User!)
            .ToListAsync(ct);
    }
    public Task<List<string>> GetActiveRoleNamesByUserIdAsync(Guid userId, CancellationToken ct = default) 
    {
        return dbContext.UserRoles
          .Where(ur => ur.UserId == userId && ur.IsActive && ur.Role!.IsActive)
          .Select(ur => ur.Role!.RoleName)
          .Distinct()
          .ToListAsync(ct);
    }

    public Task AddAsync(UserRole userRole, CancellationToken ct = default)
    {
        return dbContext.UserRoles.AddAsync(userRole, ct).AsTask();
    }

    public void Update(UserRole userRole)
    {
        dbContext.UserRoles.Update(userRole);
    }

    public Task SaveChangesAsync(CancellationToken ct = default)
    {
        return dbContext.SaveChangesAsync(ct);
    }
}
