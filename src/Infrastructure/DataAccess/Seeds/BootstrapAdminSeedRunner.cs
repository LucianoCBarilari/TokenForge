using Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Infrastructure.DataAccess.Seeds;

public sealed class BootstrapAdminSeedRunner(
    TokenForgeContext dbContext,
    IConfiguration configuration,
    ILogger<BootstrapAdminSeedRunner> logger)
{
    public async Task RunAsync(CancellationToken ct = default)
    {
        if (!configuration.GetValue("BootstrapAdmin:Enabled", false))
            return;

        var userAccount = configuration["BootstrapAdmin:UserAccount"]?.Trim();
        var email = configuration["BootstrapAdmin:Email"]?.Trim();
        var password = configuration["BootstrapAdmin:Password"];
        var roleName = configuration["BootstrapAdmin:RoleName"]?.Trim() ?? "Admin";
        var resetPasswordOnStartup = configuration.GetValue("BootstrapAdmin:ResetPasswordOnStartup", false);

        if (string.IsNullOrWhiteSpace(userAccount) ||
            string.IsNullOrWhiteSpace(email) ||
            string.IsNullOrWhiteSpace(password))
        {
            logger.LogWarning("BootstrapAdmin is enabled but missing UserAccount, Email or Password.");
            return;
        }

        var passwordHasher = new PasswordHasher<User>();
        var now = DateTime.UtcNow;

        var user = await dbContext.Users
            .FirstOrDefaultAsync(u => u.UserAccount == userAccount || u.Email == email, ct);

        if (user is null)
        {
            user = new User
            {
                UsersId = Guid.NewGuid(),
                UserAccount = userAccount,
                Email = email,
                PasswordHash = passwordHasher.HashPassword(new User(), password),
                IsActive = true,
                CreatedAt = now
            };

            await dbContext.Users.AddAsync(user, ct);
            logger.LogInformation("Bootstrap admin user created: {UserAccount}", userAccount);
        }
        else
        {
            if (!user.IsActive)
                user.IsActive = true;

            if (resetPasswordOnStartup)
            {
                user.PasswordHash = passwordHasher.HashPassword(new User(), password);
                user.UpdatedAt = now;
                logger.LogInformation("Bootstrap admin password reset for user: {UserAccount}", user.UserAccount);
            }
        }

        var role = await dbContext.Roles
            .FirstOrDefaultAsync(r => r.RoleName == roleName && r.IsActive, ct);

        if (role is null)
        {
            logger.LogWarning("Bootstrap admin role not found or inactive: {RoleName}", roleName);
            await dbContext.SaveChangesAsync(ct);
            return;
        }

        var userRole = await dbContext.UserRoles
            .FirstOrDefaultAsync(ur => ur.UserId == user.UsersId && ur.RoleId == role.RolesId, ct);

        if (userRole is null)
        {
            await dbContext.UserRoles.AddAsync(new UserRole
            {
                UserRoleId = Guid.NewGuid(),
                UserId = user.UsersId,
                RoleId = role.RolesId,
                AssignedAt = now,
                IsActive = true
            }, ct);
            logger.LogInformation("Bootstrap admin role assigned: {RoleName} -> {UserAccount}", roleName, user.UserAccount);
        }
        else if (!userRole.IsActive)
        {
            userRole.IsActive = true;
            userRole.DeactivatedAt = null;
            userRole.DeactivatedReason = null;
            logger.LogInformation("Bootstrap admin role reactivated: {RoleName} -> {UserAccount}", roleName, user.UserAccount);
        }

        await dbContext.SaveChangesAsync(ct);
    }
}
