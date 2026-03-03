using Application.Feature.UserFeature.UserDto;

namespace Application.Feature.UserRoleFeature
{
    public interface IUserRoleService
    {
        Task<Result<UserRoleResponse>> GetUserRoleByIdAsync(Guid userRoleId);
        Task<Result> AssignRoleToUserAsync(UserRoleAssignInputDto input);
        Task<Result<List<UserResponse>>> GetAllUsersFromRole(Guid roleId);
        Task<Result<List<UserRoleResponse>>> GetRolesByUserIdAsync(Guid userId);
        Task<Result> RevokeRole(UserRoleRevokeInputDto input);
    }
}


