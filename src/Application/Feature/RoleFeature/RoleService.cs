namespace Application.Feature.RoleFeature;

public class RoleService(
    IRoleStore roleStore,
    ILogger<RoleService> logger,
    RoleMapper mapper) : IRoleService
{
    public async Task<Result<List<RoleResponse>>> GetAllRoles()
    {
        var roles = await roleStore.GetAllAsync();

        if (roles.Count == 0)
        {
            logger.LogInformation("No roles found.");
        }

        return Result<List<RoleResponse>>.Success(mapper.ToResponseList(roles));
    }

    public async Task<Result<RoleResponse>> GetRoleById(Guid roleId)
    {
        var role = await roleStore.GetByIdAsync(roleId);

        if (role is null)
        {
            return Result<RoleResponse>.Failure(RoleErrors.RoleNotFound);
        }

        return Result<RoleResponse>.Success(mapper.ToResponse(role));
    }

    public async Task<Result> UpdateRole(RoleInputDto updatedRole)
    {
        var role = await roleStore.GetByIdAsync(updatedRole.RolesId);

        if (role is null)
        {
            return Result.Failure(RoleErrors.RoleNotFound);
        }

        mapper.ApplyUpdate(updatedRole, role);
        roleStore.Update(role);
        await roleStore.SaveChangesAsync();

        return Result.Success();
    }

    public async Task<Result<List<RoleResponse>>> GetRolesForUserAsync(List<UserRoleResponse> userRoles)
    {
        if (userRoles.Count == 0)
        {
            return Result<List<RoleResponse>>.Success(new List<RoleResponse>());
        }

        var roleIds = userRoles.Select(x => x.RoleId).Distinct().ToList();
        var roles = await roleStore.GetByIdsAsync(roleIds);

        return Result<List<RoleResponse>>.Success(mapper.ToResponseList(roles));
    }
}
