using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace Infrastructure.DataAccess.Migrations
{
    /// <inheritdoc />
    public partial class SeedGranularPermissionsAndPolicies : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "Permissions",
                columns: new[] { "PermissionId", "CreatedAt", "IsActive", "PermissionCode", "PermissionDescription", "PermissionName", "RevokedAt" },
                values: new object[,]
                {
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b109"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "auth.login", "Authenticate and start a session.", "Login", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10a"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "auth.logout", "Close the current authenticated session.", "Logout", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10b"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "tokens.validate", "Validate an access token.", "Validate Token", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10c"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "tokens.refresh", "Refresh an access token using a valid refresh token.", "Refresh Token", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10d"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "users.create", "Create new users.", "Create Users", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10e"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "users.update.email", "Update a user's email address.", "Update User Email", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10f"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "users.update.account", "Update a user's account name.", "Update User Account", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b110"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "users.update.password", "Update a user's password.", "Update User Password", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b111"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "users.disable", "Disable user accounts.", "Disable Users", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b112"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "users.read.roles", "Read roles assigned to users.", "Read User Roles", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b113"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "roles.update", "Update role information.", "Update Roles", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b114"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "roles.read.users", "Read users assigned to roles.", "Read Role Users", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b115"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "permissions.read", "Read permission information.", "Read Permissions", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b116"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "permissions.create", "Create new permissions.", "Create Permissions", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b117"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "permissions.update", "Update existing permissions.", "Update Permissions", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b118"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "permissions.activate", "Reactivate permissions.", "Activate Permissions", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b119"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "permissions.deactivate", "Deactivate permissions.", "Deactivate Permissions", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b11a"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "rolepermissions.assign", "Assign permissions to roles.", "Assign Role Permissions", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b11b"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "rolepermissions.revoke", "Revoke permissions from roles.", "Revoke Role Permissions", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b11c"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "rolepermissions.sync", "Synchronize permissions assigned to a role.", "Sync Role Permissions", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b11d"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "rolepermissions.read", "Read role-permission assignments.", "Read Role Permissions", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b11e"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "userroles.read", "Read user-role assignments.", "Read User Roles", null }
                });

            migrationBuilder.InsertData(
                table: "RolePermissions",
                columns: new[] { "RolePermissionId", "AssignedAt", "DeactivatedAt", "DeactivatedReason", "IsActive", "PermissionId", "RoleId" },
                values: new object[,]
                {
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c010"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b109"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c011"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10a"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c012"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10b"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c013"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10c"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c014"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10d"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c015"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10e"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c016"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10f"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c017"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b110"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c018"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b111"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c019"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b112"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c01a"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b113"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c01b"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b114"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c01c"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b115"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c01d"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b116"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c01e"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b117"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c01f"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b118"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c020"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b119"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c021"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b11a"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c022"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b11b"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c023"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b11c"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c024"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b11d"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c025"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b11e"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c026"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b109"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a002") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c027"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10a"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a002") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c028"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10b"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a002") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c029"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10c"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a002") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c02a"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10d"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a002") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c02b"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10e"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a002") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c02c"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10f"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a002") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c02d"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b110"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a002") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c02e"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b111"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a002") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c02f"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b112"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a002") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c030"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b113"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a002") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c031"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b114"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a002") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c032"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b11e"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a002") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c033"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b11d"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a002") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c034"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b109"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a003") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c035"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10a"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a003") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c036"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10b"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a003") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c037"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10c"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a003") }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c010"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c011"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c012"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c013"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c014"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c015"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c016"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c017"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c018"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c019"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c01a"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c01b"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c01c"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c01d"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c01e"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c01f"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c020"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c021"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c022"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c023"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c024"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c025"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c026"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c027"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c028"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c029"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c02a"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c02b"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c02c"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c02d"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c02e"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c02f"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c030"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c031"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c032"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c033"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c034"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c035"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c036"));

            migrationBuilder.DeleteData(
                table: "RolePermissions",
                keyColumn: "RolePermissionId",
                keyValue: new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c037"));

            migrationBuilder.DeleteData(
                table: "Permissions",
                keyColumn: "PermissionId",
                keyValue: new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b109"));

            migrationBuilder.DeleteData(
                table: "Permissions",
                keyColumn: "PermissionId",
                keyValue: new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10a"));

            migrationBuilder.DeleteData(
                table: "Permissions",
                keyColumn: "PermissionId",
                keyValue: new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10b"));

            migrationBuilder.DeleteData(
                table: "Permissions",
                keyColumn: "PermissionId",
                keyValue: new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10c"));

            migrationBuilder.DeleteData(
                table: "Permissions",
                keyColumn: "PermissionId",
                keyValue: new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10d"));

            migrationBuilder.DeleteData(
                table: "Permissions",
                keyColumn: "PermissionId",
                keyValue: new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10e"));

            migrationBuilder.DeleteData(
                table: "Permissions",
                keyColumn: "PermissionId",
                keyValue: new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10f"));

            migrationBuilder.DeleteData(
                table: "Permissions",
                keyColumn: "PermissionId",
                keyValue: new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b110"));

            migrationBuilder.DeleteData(
                table: "Permissions",
                keyColumn: "PermissionId",
                keyValue: new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b111"));

            migrationBuilder.DeleteData(
                table: "Permissions",
                keyColumn: "PermissionId",
                keyValue: new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b112"));

            migrationBuilder.DeleteData(
                table: "Permissions",
                keyColumn: "PermissionId",
                keyValue: new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b113"));

            migrationBuilder.DeleteData(
                table: "Permissions",
                keyColumn: "PermissionId",
                keyValue: new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b114"));

            migrationBuilder.DeleteData(
                table: "Permissions",
                keyColumn: "PermissionId",
                keyValue: new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b115"));

            migrationBuilder.DeleteData(
                table: "Permissions",
                keyColumn: "PermissionId",
                keyValue: new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b116"));

            migrationBuilder.DeleteData(
                table: "Permissions",
                keyColumn: "PermissionId",
                keyValue: new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b117"));

            migrationBuilder.DeleteData(
                table: "Permissions",
                keyColumn: "PermissionId",
                keyValue: new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b118"));

            migrationBuilder.DeleteData(
                table: "Permissions",
                keyColumn: "PermissionId",
                keyValue: new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b119"));

            migrationBuilder.DeleteData(
                table: "Permissions",
                keyColumn: "PermissionId",
                keyValue: new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b11a"));

            migrationBuilder.DeleteData(
                table: "Permissions",
                keyColumn: "PermissionId",
                keyValue: new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b11b"));

            migrationBuilder.DeleteData(
                table: "Permissions",
                keyColumn: "PermissionId",
                keyValue: new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b11c"));

            migrationBuilder.DeleteData(
                table: "Permissions",
                keyColumn: "PermissionId",
                keyValue: new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b11d"));

            migrationBuilder.DeleteData(
                table: "Permissions",
                keyColumn: "PermissionId",
                keyValue: new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b11e"));
        }
    }
}
