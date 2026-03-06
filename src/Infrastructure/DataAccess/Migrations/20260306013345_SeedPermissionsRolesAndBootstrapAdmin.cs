using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace Infrastructure.DataAccess.Migrations
{
    /// <inheritdoc />
    public partial class SeedPermissionsRolesAndBootstrapAdmin : Migration
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
                    { new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b108"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), true, "userroles.revoke", "Revoke role assignments from users.", "Revoke User Roles", null }
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
                    { new Guid("4fa8aab1-4ee8-4e54-b1f0-8af8f022c00f"), new DateTime(2026, 3, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, null, true, new Guid("7cc9d620-07c7-40d2-a5a7-95e0d1c0b101"), new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a003") }
                });

            migrationBuilder.CreateIndex(
                name: "IX_Permissions_PermissionCode",
                table: "Permissions",
                column: "PermissionCode",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RolePermissions_PermissionId",
                table: "RolePermissions",
                column: "PermissionId");

            migrationBuilder.CreateIndex(
                name: "IX_RolePermissions_RoleId_PermissionId",
                table: "RolePermissions",
                columns: new[] { "RoleId", "PermissionId" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "RolePermissions");

            migrationBuilder.DropTable(
                name: "Permissions");

            migrationBuilder.DeleteData(
                table: "Roles",
                keyColumn: "RolesId",
                keyValue: new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a001"));

            migrationBuilder.DeleteData(
                table: "Roles",
                keyColumn: "RolesId",
                keyValue: new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a002"));

            migrationBuilder.DeleteData(
                table: "Roles",
                keyColumn: "RolesId",
                keyValue: new Guid("4d2d7af9-2c7f-4f42-8a3d-7e7e26a6a003"));
        }
    }
}
