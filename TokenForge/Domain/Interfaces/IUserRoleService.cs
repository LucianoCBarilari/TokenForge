
using TokenForge.Application.Dtos.RoleDto;
using TokenForge.Application.Dtos.UserDto;
using TokenForge.Application.Dtos.UserRoleDto;
using TokenForge.Domain.Shared;

namespace TokenForge.Domain.Interfaces
{
    public interface IUserRoleService
    {
       Task<Result<List<UserRoleResponse>>> GetAllUserRolesAsync();
       Task<Result<UserRoleResponse>> GetUserRoleByIdAsync(Guid userRoleId);
       Task<Result> AssignRoleToUserAsync(AssignRoleRequest assignRole);
       Task<Result<List<UserResponse>>> GetAllUsersFromRole(Guid roleId);
       Task<Result<List<UserRoleResponse>>> GetRolesByUserIdAsync(Guid userId);
       Task<Result> RevokeRole(RevokeRoleRequest RoleToRevoke);
    }
}


