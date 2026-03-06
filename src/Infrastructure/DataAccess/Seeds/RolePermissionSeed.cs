using Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.DataAccess.Seeds;

public static class RolePermissionSeed
{
    public static void Configure(ModelBuilder modelBuilder)
    {
        var assignedAt = new DateTime(2026, 03, 01, 0, 0, 0, DateTimeKind.Utc);

        modelBuilder.Entity<RolePermission>().HasData(
            // Admin: full set
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C001"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionTokensRevokeCurrentId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C002"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionTokensRevokeAllId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C003"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionUsersReadId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C004"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionUsersWriteId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C005"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionRolesReadId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C006"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionRolesWriteId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C007"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionUserRolesAssignId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C008"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionUserRolesRevokeId, AssignedAt = assignedAt, IsActive = true },

            // Manager: operational set (no global token revoke, no role write)
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C009"), RoleId = AuthSeedIds.ManagerRoleId, PermissionId = AuthSeedIds.PermissionTokensRevokeCurrentId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C00A"), RoleId = AuthSeedIds.ManagerRoleId, PermissionId = AuthSeedIds.PermissionUsersReadId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C00B"), RoleId = AuthSeedIds.ManagerRoleId, PermissionId = AuthSeedIds.PermissionUsersWriteId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C00C"), RoleId = AuthSeedIds.ManagerRoleId, PermissionId = AuthSeedIds.PermissionRolesReadId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C00D"), RoleId = AuthSeedIds.ManagerRoleId, PermissionId = AuthSeedIds.PermissionUserRolesAssignId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C00E"), RoleId = AuthSeedIds.ManagerRoleId, PermissionId = AuthSeedIds.PermissionUserRolesRevokeId, AssignedAt = assignedAt, IsActive = true },

            // User: minimal self-service set
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C00F"), RoleId = AuthSeedIds.UserRoleId, PermissionId = AuthSeedIds.PermissionTokensRevokeCurrentId, AssignedAt = assignedAt, IsActive = true }
        );
    }
}
