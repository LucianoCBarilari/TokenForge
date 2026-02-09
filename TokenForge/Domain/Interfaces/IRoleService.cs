using TokenForge.Application.Dtos.RoleDto;
using TokenForge.Application.Dtos.UserRoleDto;
using TokenForge.Domain.Shared;

namespace TokenForge.Domain.Interfaces
{
    public interface IRoleService
    {
        Task<Result<List<RoleResponse>>> GetAllRoles();
        Task<Result<RoleResponse>> GetRoleById(Guid roleId);
        Task<Result> UpdateRole(UpdateRoleRequest UpdatedRole);
        Task<Result<List<RoleResponse>>> GetRolesForUserAsync(List<UserRoleResponse> userRoles);
    }
}


