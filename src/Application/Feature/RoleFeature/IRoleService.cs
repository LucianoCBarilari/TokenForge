namespace Application.Feature.RoleFeature;

public interface IRoleService
{
    Task<Result<List<RoleResponse>>> GetAllRoles();
    Task<Result<RoleResponse>> GetRoleById(Guid roleId);
    Task<Result> UpdateRole(RoleInputDto updatedRole);
    Task<Result<List<RoleResponse>>> GetRolesForUserAsync(List<UserRoleResponse> userRoles);
}


