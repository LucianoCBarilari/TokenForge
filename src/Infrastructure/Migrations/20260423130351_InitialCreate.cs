using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Permissions",
                columns: table => new
                {
                    PermissionId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PermissionCode = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    PermissionName = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    PermissionDescription = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    IsActive = table.Column<bool>(type: "bit", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    RevokedAt = table.Column<DateTime>(type: "datetime2", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Permissions", x => x.PermissionId);
                });

            migrationBuilder.CreateTable(
                name: "Roles",
                columns: table => new
                {
                    RolesId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RoleName = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    RoleDescription = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    IsActive = table.Column<bool>(type: "bit", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    RevokedAt = table.Column<DateTime>(type: "datetime2", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Roles", x => x.RolesId);
                });

            migrationBuilder.CreateTable(
                name: "Users",
                columns: table => new
                {
                    UsersId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Email = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    UserAccount = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    PasswordHash = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    IsActive = table.Column<bool>(type: "bit", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime2", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Users", x => x.UsersId);
                });

            migrationBuilder.CreateTable(
                name: "RolePermissions",
                columns: table => new
                {
                    RolePermissionId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RoleId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PermissionId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    AssignedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    IsActive = table.Column<bool>(type: "bit", nullable: false),
                    DeactivatedAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    DeactivatedReason = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RolePermissions", x => x.RolePermissionId);
                    table.ForeignKey(
                        name: "FK_RolePermissions_Permissions_PermissionId",
                        column: x => x.PermissionId,
                        principalTable: "Permissions",
                        principalColumn: "PermissionId",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_RolePermissions_Roles_RoleId",
                        column: x => x.RoleId,
                        principalTable: "Roles",
                        principalColumn: "RolesId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "LoginAttempts",
                columns: table => new
                {
                    LoginAttemptID = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserAttempt = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    FailedAttempts = table.Column<int>(type: "int", nullable: false),
                    LastAttemptAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    LockedUntil = table.Column<DateTime>(type: "datetime2", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LoginAttempts", x => x.LoginAttemptID);
                    table.ForeignKey(
                        name: "FK_LoginAttempts_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "UsersId",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "RefreshTokens",
                columns: table => new
                {
                    RefreshTokensId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Token = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    RevokedAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    ReplacedByToken = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    IPAddress = table.Column<string>(type: "nvarchar(45)", maxLength: 45, nullable: true),
                    UserAgent = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RefreshTokens", x => x.RefreshTokensId);
                    table.ForeignKey(
                        name: "FK_RefreshTokens_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "UsersId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "UserRoles",
                columns: table => new
                {
                    UserRoleId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RoleId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    AssignedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    IsActive = table.Column<bool>(type: "bit", nullable: false),
                    DeactivatedAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    DeactivatedReason = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserRoles", x => x.UserRoleId);
                    table.ForeignKey(
                        name: "FK_UserRoles_Roles_RoleId",
                        column: x => x.RoleId,
                        principalTable: "Roles",
                        principalColumn: "RolesId",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_UserRoles_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "UsersId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.InsertData(
                table: "Permissions",
                columns: new[] { "PermissionId", "CreatedAt", "IsActive", "PermissionCode", "PermissionDescription", "PermissionName", "RevokedAt" },
                values: new object[,]
                {
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b101"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "tokens.revoke.current", "Revoke refresh token of the current session.", "Revoke Current Token", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b102"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "tokens.revoke.all", "Revoke all refresh tokens for a target user.", "Revoke All User Tokens", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b103"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "users.read", "Read user information.", "Read Users", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b104"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "users.write", "Create or update users.", "Write Users", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b105"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "roles.read", "Read role information.", "Read Roles", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b106"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "roles.write", "Create or update roles.", "Write Roles", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b107"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "userroles.assign", "Assign roles to users.", "Assign User Roles", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b108"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "userroles.revoke", "Revoke role assignments from users.", "Revoke User Roles", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b109"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "auth.login", "Authenticate and start a session.", "Login", null },
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10a"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "auth.logout", "Close the current authenticated session.", "Logout", null },
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
                table: "Roles",
                columns: new[] { "RolesId", "CreatedAt", "IsActive", "RevokedAt", "RoleDescription", "RoleName" },
                values: new object[,]
                {
                    { new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, null, "System administrator", "Admin" },
                    { new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a002"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, null, "Team manager with operational permissions", "Manager" },
                    { new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a003"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, null, "Basic user role", "User" }
                });

            migrationBuilder.InsertData(
                table: "RolePermissions",
                columns: new[] { "RolePermissionId", "AssignedAt", "DeactivatedAt", "DeactivatedReason", "IsActive", "PermissionId", "RoleId" },
                values: new object[,]
                {
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c001"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b101"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c002"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b102"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c003"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b103"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c004"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b104"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c005"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b105"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c006"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b106"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c007"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b107"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c008"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b108"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c009"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b101"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a002") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c00a"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b103"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a002") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c00b"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b104"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a002") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c00c"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b105"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a002") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c00d"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b107"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a002") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c00e"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b108"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a002") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c00f"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b101"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a003") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c010"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b109"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c011"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10a"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001") },
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
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c037"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b10c"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a003") }
                });

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_UserAttempt",
                table: "LoginAttempts",
                column: "UserAttempt");

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_UserId_LastAttemptAt",
                table: "LoginAttempts",
                columns: new[] { "UserId", "LastAttemptAt" });

            migrationBuilder.CreateIndex(
                name: "IX_Permissions_PermissionCode",
                table: "Permissions",
                column: "PermissionCode",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_Token",
                table: "RefreshTokens",
                column: "Token",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_UserId",
                table: "RefreshTokens",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_RolePermissions_PermissionId",
                table: "RolePermissions",
                column: "PermissionId");

            migrationBuilder.CreateIndex(
                name: "IX_RolePermissions_RoleId_PermissionId",
                table: "RolePermissions",
                columns: new[] { "RoleId", "PermissionId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_UserRoles_RoleId",
                table: "UserRoles",
                column: "RoleId");

            migrationBuilder.CreateIndex(
                name: "IX_UserRoles_UserId",
                table: "UserRoles",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_Users_Email",
                table: "Users",
                column: "Email",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Users_UserAccount",
                table: "Users",
                column: "UserAccount",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "LoginAttempts");

            migrationBuilder.DropTable(
                name: "RefreshTokens");

            migrationBuilder.DropTable(
                name: "RolePermissions");

            migrationBuilder.DropTable(
                name: "UserRoles");

            migrationBuilder.DropTable(
                name: "Permissions");

            migrationBuilder.DropTable(
                name: "Roles");

            migrationBuilder.DropTable(
                name: "Users");
        }
    }
}
