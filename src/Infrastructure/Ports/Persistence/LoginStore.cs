using Application.Abstractions.Persistence;
using Application.Feature.AuthFeature.AuthDto;
using Infrastructure.DataAccess;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Ports.Persistence;

public class LoginStore(TokenForgeContext dbContext) : ILoginStore
{
    public async Task<UserWithLastAttemptDto?> GetUserWithLastLoginAsync(string userAccount)
    {
        return await dbContext.Users
            .Where(u => u.IsActive && u.UserAccount == userAccount)
            .GroupJoin(
                dbContext.LoginAttempts,
                u => u.UsersId,
                la => la.UserId,
                (u, attempts) => new { u, attempts })
            .Select(u => new UserWithLastAttemptDto
            {
                UsersId = u.u.UsersId,
                UserAccount = u.u.UserAccount,
                Email = u.u.Email,
                PasswordHash = u.u.PasswordHash,
                IsActive = u.u.IsActive,
                FailedAttempts = u.attempts
                    .OrderByDescending(a => a.LastAttemptAt)
                    .Select(a => a.FailedAttempts)
                    .FirstOrDefault(),
                LastAttemptAt = u.attempts
                    .OrderByDescending(a => a.LastAttemptAt)
                    .Select(a => (DateTime?)a.LastAttemptAt)
                    .FirstOrDefault(),
                LockedUntil = u.attempts
                    .OrderByDescending(a => a.LastAttemptAt)
                    .Select(a => a.LockedUntil)
                    .FirstOrDefault()
            })
            .FirstOrDefaultAsync();
    }

    public async Task<UserRolesPermissionsDto> GetUserRolesAndPermissionsAsync(Guid userId, CancellationToken ct = default)
    {
        var roles = await dbContext.UserRoles
            .AsNoTracking()
            .Where(ur => ur.UserId == userId && ur.IsActive && ur.Role != null && ur.Role.IsActive)
            .Select(ur => new
            {
                ur.RoleId,
                RoleName = ur.Role!.RoleName
            })
            .Distinct()
            .ToListAsync(ct);

        var response = new UserRolesPermissionsDto
        {
            Roles = roles.ToDictionary(role => role.RoleId, role => role.RoleName ?? string.Empty)
        };

        if (roles.Count == 0)
            return response;

        var roleIds = roles.Select(role => role.RoleId).ToList();

        var permissions = await dbContext.RolePermissions
            .AsNoTracking()
            .Where(rp =>
                roleIds.Contains(rp.RoleId) &&
                rp.IsActive &&
                rp.Permission != null &&
                rp.Permission.IsActive)
            .Select(rp => new
            {
                rp.PermissionId,
                PermissionCode = rp.Permission!.PermissionCode
            })
            .Distinct()
            .ToListAsync(ct);

        response.Permissions = permissions.ToDictionary(
            permission => permission.PermissionId,
            permission => permission.PermissionCode ?? string.Empty);

        return response;
    }
}
