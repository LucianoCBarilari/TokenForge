using Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.DataAccess.Seeds;

public static class PermissionSeed
{
    public static void Configure(ModelBuilder modelBuilder)
    {
        var createdAt = new DateTime(2026, 03, 01, 0, 0, 0, DateTimeKind.Utc);

        modelBuilder.Entity<Permission>().HasData(
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionTokensRevokeCurrentId,
                PermissionCode = "tokens.revoke.current",
                PermissionName = "Revoke Current Token",
                PermissionDescription = "Revoke refresh token of the current session.",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionTokensRevokeAllId,
                PermissionCode = "tokens.revoke.all",
                PermissionName = "Revoke All User Tokens",
                PermissionDescription = "Revoke all refresh tokens for a target user.",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionUsersReadId,
                PermissionCode = "users.read",
                PermissionName = "Read Users",
                PermissionDescription = "Read user information.",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionUsersWriteId,
                PermissionCode = "users.write",
                PermissionName = "Write Users",
                PermissionDescription = "Create or update users.",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionRolesReadId,
                PermissionCode = "roles.read",
                PermissionName = "Read Roles",
                PermissionDescription = "Read role information.",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionRolesWriteId,
                PermissionCode = "roles.write",
                PermissionName = "Write Roles",
                PermissionDescription = "Create or update roles.",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionUserRolesAssignId,
                PermissionCode = "userroles.assign",
                PermissionName = "Assign User Roles",
                PermissionDescription = "Assign roles to users.",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionUserRolesRevokeId,
                PermissionCode = "userroles.revoke",
                PermissionName = "Revoke User Roles",
                PermissionDescription = "Revoke role assignments from users.",
                IsActive = true,
                CreatedAt = createdAt
            });
    }
}
