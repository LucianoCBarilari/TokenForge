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
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C010"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionAuthLoginId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C011"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionAuthLogoutId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C012"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionTokensValidateId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C013"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionTokensRefreshId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C001"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionTokensRevokeCurrentId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C002"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionTokensRevokeAllId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C003"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionUsersReadId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C004"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionUsersWriteId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C014"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionUsersCreateId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C015"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionUsersUpdateEmailId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C016"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionUsersUpdateAccountId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C017"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionUsersUpdatePasswordId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C018"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionUsersDisableId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C019"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionUsersReadRolesId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C005"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionRolesReadId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C006"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionRolesWriteId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C01A"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionRolesUpdateId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C01B"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionRolesReadUsersId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C01C"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionPermissionsReadId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C01D"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionPermissionsCreateId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C01E"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionPermissionsUpdateId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C01F"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionPermissionsActivateId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C020"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionPermissionsDeactivateId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C021"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionRolePermissionsAssignId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C022"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionRolePermissionsRevokeId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C023"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionRolePermissionsSyncId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C024"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionRolePermissionsReadId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C007"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionUserRolesAssignId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C008"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionUserRolesRevokeId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C025"), RoleId = AuthSeedIds.AdminRoleId, PermissionId = AuthSeedIds.PermissionUserRolesReadId, AssignedAt = assignedAt, IsActive = true },

            // Manager: operational set (no global token revoke, no role write)
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C026"), RoleId = AuthSeedIds.ManagerRoleId, PermissionId = AuthSeedIds.PermissionAuthLoginId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C027"), RoleId = AuthSeedIds.ManagerRoleId, PermissionId = AuthSeedIds.PermissionAuthLogoutId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C028"), RoleId = AuthSeedIds.ManagerRoleId, PermissionId = AuthSeedIds.PermissionTokensValidateId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C029"), RoleId = AuthSeedIds.ManagerRoleId, PermissionId = AuthSeedIds.PermissionTokensRefreshId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C009"), RoleId = AuthSeedIds.ManagerRoleId, PermissionId = AuthSeedIds.PermissionTokensRevokeCurrentId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C00A"), RoleId = AuthSeedIds.ManagerRoleId, PermissionId = AuthSeedIds.PermissionUsersReadId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C00B"), RoleId = AuthSeedIds.ManagerRoleId, PermissionId = AuthSeedIds.PermissionUsersWriteId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C02A"), RoleId = AuthSeedIds.ManagerRoleId, PermissionId = AuthSeedIds.PermissionUsersCreateId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C02B"), RoleId = AuthSeedIds.ManagerRoleId, PermissionId = AuthSeedIds.PermissionUsersUpdateEmailId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C02C"), RoleId = AuthSeedIds.ManagerRoleId, PermissionId = AuthSeedIds.PermissionUsersUpdateAccountId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C02D"), RoleId = AuthSeedIds.ManagerRoleId, PermissionId = AuthSeedIds.PermissionUsersUpdatePasswordId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C02E"), RoleId = AuthSeedIds.ManagerRoleId, PermissionId = AuthSeedIds.PermissionUsersDisableId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C02F"), RoleId = AuthSeedIds.ManagerRoleId, PermissionId = AuthSeedIds.PermissionUsersReadRolesId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C00C"), RoleId = AuthSeedIds.ManagerRoleId, PermissionId = AuthSeedIds.PermissionRolesReadId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C030"), RoleId = AuthSeedIds.ManagerRoleId, PermissionId = AuthSeedIds.PermissionRolesUpdateId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C031"), RoleId = AuthSeedIds.ManagerRoleId, PermissionId = AuthSeedIds.PermissionRolesReadUsersId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C00D"), RoleId = AuthSeedIds.ManagerRoleId, PermissionId = AuthSeedIds.PermissionUserRolesAssignId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C00E"), RoleId = AuthSeedIds.ManagerRoleId, PermissionId = AuthSeedIds.PermissionUserRolesRevokeId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C032"), RoleId = AuthSeedIds.ManagerRoleId, PermissionId = AuthSeedIds.PermissionUserRolesReadId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C033"), RoleId = AuthSeedIds.ManagerRoleId, PermissionId = AuthSeedIds.PermissionRolePermissionsReadId, AssignedAt = assignedAt, IsActive = true },

            // User: minimal self-service set
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C00F"), RoleId = AuthSeedIds.UserRoleId, PermissionId = AuthSeedIds.PermissionTokensRevokeCurrentId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C034"), RoleId = AuthSeedIds.UserRoleId, PermissionId = AuthSeedIds.PermissionAuthLoginId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C035"), RoleId = AuthSeedIds.UserRoleId, PermissionId = AuthSeedIds.PermissionAuthLogoutId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C036"), RoleId = AuthSeedIds.UserRoleId, PermissionId = AuthSeedIds.PermissionTokensValidateId, AssignedAt = assignedAt, IsActive = true },
            new RolePermission { RolePermissionId = Guid.Parse("4FA8AAB1-4EE8-4E54-B1F0-8AF8F022C037"), RoleId = AuthSeedIds.UserRoleId, PermissionId = AuthSeedIds.PermissionTokensRefreshId, AssignedAt = assignedAt, IsActive = true }
        );
    }
}
