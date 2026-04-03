using Application.Abstractions.Persistence;
using Domain.Entities;
using Infrastructure.DataAccess;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Ports.Persistence;

public class EfUserRoleStore(TokenForgeContext dbContext) : IUserRoleStore
{
    public async Task<UserRole?> GetAsync(Guid userId, Guid roleId, CancellationToken ct = default)
    {
        return await dbContext.UserRoles
            .FirstOrDefaultAsync(x => x.UserId == userId && x.RoleId == roleId, ct);
    }

    public async Task<UserRole?> GetByIdAsync(Guid userRoleId, CancellationToken ct = default)
    {
        return await dbContext.UserRoles
            .Include(x => x.User)
            .Include(x => x.Role)
            .FirstOrDefaultAsync(x => x.UserRoleId == userRoleId, ct);
    }

    public async Task<List<UserRole>> GetActiveByUserIdAsync(Guid userId, CancellationToken ct = default)
    {
        return await dbContext.UserRoles
            .AsNoTracking()
            .Include(x => x.Role)
            .Where(x => x.UserId == userId && x.IsActive)
            .ToListAsync(ct);
    }

    public async Task<List<User>> GetActiveUsersByRoleIdAsync(Guid roleId, CancellationToken ct = default)
    {
        return await dbContext.UserRoles
            .AsNoTracking()
            .Where(x => x.RoleId == roleId && x.IsActive)
            .Include(x => x.User)
            .Select(x => x.User!)
            .ToListAsync(ct);
    }
    public async Task<List<string>> GetActiveRoleNamesByUserIdAsync(Guid userId, CancellationToken ct = default) 
    {
        return await dbContext.UserRoles
          .Where(ur => ur.UserId == userId && ur.IsActive && ur.Role!.IsActive)
          .Select(ur => ur.Role!.RoleName)
          .Distinct()
          .ToListAsync(ct);
    }
    public async Task<List<Guid>> GetActiveRoleIdsByUserIdAsync(Guid userId, CancellationToken ct = default)
    {
        return await  dbContext.UserRoles
              .AsNoTracking()
              .Include(ur => ur.Role)
              .Where(ur => ur.UserId == userId 
                        && ur.IsActive
                        && ur.Role.IsActive)
              .Select(ur => ur.Role.RolesId)
              .Distinct()
              .ToListAsync(ct);
    }

    public async Task AddAsync(UserRole userRole, CancellationToken ct = default)
    {
        await dbContext.UserRoles.AddAsync(userRole, ct);
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
