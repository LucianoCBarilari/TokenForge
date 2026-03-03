using Application.Abstractions.Common;
using Application.Feature.UserFeature;
using Application.Feature.UserFeature.UserDto;

namespace Application.Feature.UserRoleFeature;

public class UserRoleService(
    IUserStore userStore,
    IRoleStore roleStore,
    IUserRoleStore userRoleStore,
    UserRoleMapper mapper,
    UserMapper userMapper,
    IClock clock) : IUserRoleService
{
    public async Task<Result> AssignRoleToUserAsync(UserRoleAssignInputDto input)
    {
        var user = await userStore.GetByIdAsync(input.UserId);
        if (user is null)
            return Result.Failure(UserRoleErrors.UserNotFound);

        var role = await roleStore.GetByIdAsync(input.RoleId);
        if (role is null)
            return Result.Failure(UserRoleErrors.RoleNotFound);

        var assignment = await userRoleStore.GetAsync(input.UserId, input.RoleId);
        if (assignment is not null)
        {
            if (assignment.IsActive)
                return Result.Failure(UserRoleErrors.UserAlreadyInRole);

            assignment.IsActive = true;
            assignment.DeactivatedAt = null;
            assignment.DeactivatedReason = null;
            userRoleStore.Update(assignment);
            await userRoleStore.SaveChangesAsync();
            return Result.Success();
        }

        var userRole = new UserRole
        {
            UserId = input.UserId,
            RoleId = input.RoleId,
            AssignedAt = clock.UtcNow,
            IsActive = true
        };

        await userRoleStore.AddAsync(userRole);
        await userRoleStore.SaveChangesAsync();
        return Result.Success();
    }

    public async Task<Result<UserRoleResponse>> GetUserRoleByIdAsync(Guid userRoleId)
    {
        var userRole = await userRoleStore.GetByIdAsync(userRoleId);
        if (userRole is null)
            return Result<UserRoleResponse>.Failure(UserRoleErrors.UserRoleNotFound);

        return Result<UserRoleResponse>.Success(mapper.ToResponse(userRole));
    }

    public async Task<Result> RevokeRole(UserRoleRevokeInputDto input)
    {
        var assignment = await userRoleStore.GetAsync(input.UserId, input.RoleId);
        if (assignment is null || !assignment.IsActive)
            return Result.Failure(UserRoleErrors.ActiveAssignmentNotFound);

        assignment.IsActive = false;
        assignment.DeactivatedAt = clock.UtcNow;
        assignment.DeactivatedReason = input.Reason;

        userRoleStore.Update(assignment);
        await userRoleStore.SaveChangesAsync();
        return Result.Success();
    }

    public async Task<Result<List<UserRoleResponse>>> GetRolesByUserIdAsync(Guid userId)
    {
        var userRoles = await userRoleStore.GetActiveByUserIdAsync(userId);
        return Result<List<UserRoleResponse>>.Success(mapper.ToResponseList(userRoles));
    }

    public async Task<Result<List<UserResponse>>> GetAllUsersFromRole(Guid roleId)
    {
        var role = await roleStore.GetByIdAsync(roleId);
        if (role is null)
            return Result<List<UserResponse>>.Failure(UserRoleErrors.RoleNotFound);

        var users = await userRoleStore.GetActiveUsersByRoleIdAsync(roleId);
        return Result<List<UserResponse>>.Success(userMapper.ToResponseList(users));
    }
}
