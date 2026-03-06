using Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.DataAccess.Seeds;

public static class RoleSeed
{
    public static void Configure(ModelBuilder modelBuilder)
    {
        var createdAt = new DateTime(2026, 03, 01, 0, 0, 0, DateTimeKind.Utc);

        modelBuilder.Entity<Role>().HasData(
            new Role
            {
                RolesId = AuthSeedIds.AdminRoleId,
                RoleName = "Admin",
                RoleDescription = "System administrator",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Role
            {
                RolesId = AuthSeedIds.ManagerRoleId,
                RoleName = "Manager",
                RoleDescription = "Team manager with operational permissions",
                IsActive = true,
                CreatedAt = createdAt
            },
            new Role
            {
                RolesId = AuthSeedIds.UserRoleId,
                RoleName = "User",
                RoleDescription = "Basic user role",
                IsActive = true,
                CreatedAt = createdAt
            });
    }
}
