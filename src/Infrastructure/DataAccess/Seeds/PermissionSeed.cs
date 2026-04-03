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
                PermissionId = AuthSeedIds.PermissionAuthLoginId,
                PermissionCode = "auth.login",
                PermissionName = "Login",
                PermissionDescription = "Authenticate and start a session.",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionAuthLogoutId,
                PermissionCode = "auth.logout",
                PermissionName = "Logout",
                PermissionDescription = "Close the current authenticated session.",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionTokensValidateId,
                PermissionCode = "tokens.validate",
                PermissionName = "Validate Token",
                PermissionDescription = "Validate an access token.",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionTokensRefreshId,
                PermissionCode = "tokens.refresh",
                PermissionName = "Refresh Token",
                PermissionDescription = "Refresh an access token using a valid refresh token.",
                IsActive = true,
                CreatedAt = createdAt
            },
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
                PermissionId = AuthSeedIds.PermissionUsersCreateId,
                PermissionCode = "users.create",
                PermissionName = "Create Users",
                PermissionDescription = "Create new users.",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionUsersUpdateEmailId,
                PermissionCode = "users.update.email",
                PermissionName = "Update User Email",
                PermissionDescription = "Update a user's email address.",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionUsersUpdateAccountId,
                PermissionCode = "users.update.account",
                PermissionName = "Update User Account",
                PermissionDescription = "Update a user's account name.",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionUsersUpdatePasswordId,
                PermissionCode = "users.update.password",
                PermissionName = "Update User Password",
                PermissionDescription = "Update a user's password.",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionUsersDisableId,
                PermissionCode = "users.disable",
                PermissionName = "Disable Users",
                PermissionDescription = "Disable user accounts.",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionUsersReadRolesId,
                PermissionCode = "users.read.roles",
                PermissionName = "Read User Roles",
                PermissionDescription = "Read roles assigned to users.",
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
                PermissionId = AuthSeedIds.PermissionRolesUpdateId,
                PermissionCode = "roles.update",
                PermissionName = "Update Roles",
                PermissionDescription = "Update role information.",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionRolesReadUsersId,
                PermissionCode = "roles.read.users",
                PermissionName = "Read Role Users",
                PermissionDescription = "Read users assigned to roles.",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionPermissionsReadId,
                PermissionCode = "permissions.read",
                PermissionName = "Read Permissions",
                PermissionDescription = "Read permission information.",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionPermissionsCreateId,
                PermissionCode = "permissions.create",
                PermissionName = "Create Permissions",
                PermissionDescription = "Create new permissions.",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionPermissionsUpdateId,
                PermissionCode = "permissions.update",
                PermissionName = "Update Permissions",
                PermissionDescription = "Update existing permissions.",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionPermissionsActivateId,
                PermissionCode = "permissions.activate",
                PermissionName = "Activate Permissions",
                PermissionDescription = "Reactivate permissions.",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionPermissionsDeactivateId,
                PermissionCode = "permissions.deactivate",
                PermissionName = "Deactivate Permissions",
                PermissionDescription = "Deactivate permissions.",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionRolePermissionsAssignId,
                PermissionCode = "rolepermissions.assign",
                PermissionName = "Assign Role Permissions",
                PermissionDescription = "Assign permissions to roles.",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionRolePermissionsRevokeId,
                PermissionCode = "rolepermissions.revoke",
                PermissionName = "Revoke Role Permissions",
                PermissionDescription = "Revoke permissions from roles.",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionRolePermissionsSyncId,
                PermissionCode = "rolepermissions.sync",
                PermissionName = "Sync Role Permissions",
                PermissionDescription = "Synchronize permissions assigned to a role.",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionRolePermissionsReadId,
                PermissionCode = "rolepermissions.read",
                PermissionName = "Read Role Permissions",
                PermissionDescription = "Read role-permission assignments.",
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
            },
            new Permission
            {
                PermissionId = AuthSeedIds.PermissionUserRolesReadId,
                PermissionCode = "userroles.read",
                PermissionName = "Read User Roles",
                PermissionDescription = "Read user-role assignments.",
                IsActive = true,
                CreatedAt = createdAt
            });
    }
}
