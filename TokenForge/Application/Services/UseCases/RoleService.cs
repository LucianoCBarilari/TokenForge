using TokenForge.Application.Dtos.RoleDto;
using TokenForge.Application.Dtos.UserRoleDto;
using TokenForge.Domain.Errors;
using TokenForge.Domain.Interfaces;
using TokenForge.Domain.Shared;

namespace TokenForge.Application.Services.UseCases
{
    public class RoleService(
        IRoleRepository roleRepository,
        ILogger<RoleService> logger
        ) : IRoleService
    {
        public async Task<Result<List<RoleResponse>>> GetAllRoles() 
        {
            try
            {
                var roles = await roleRepository.GetAllAsync();
                var mapped = roles.Select(role => new RoleResponse
                {
                    RolesId = role.RolesId,
                    RoleName = role.RoleName,
                    RoleDescription = role.RoleDescription,
                    IsActive = role.IsActive,
                    CreatedAt = role.CreatedAt
                }).ToList();

                return Result<List<RoleResponse>>.Success(mapped);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error occurred while getting all roles.");
                return RoleErrors.OperationFailed;
            }
        }

        public async Task<Result<RoleResponse>> GetRoleById(Guid roleId) 
        {
            try
            {
                var role = await roleRepository.GetByIdAsync(roleId);
                if (role == null)
                {
                    return RoleErrors.RoleNotFound;
                }
               
                var mapped = new RoleResponse
                {
                    RolesId = role.RolesId,
                    RoleName = role.RoleName,
                    RoleDescription = role.RoleDescription,
                    IsActive = role.IsActive,
                    CreatedAt = role.CreatedAt
                };
                return Result<RoleResponse>.Success(mapped);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error occurred while getting role by ID {RoleId}.", roleId);
                return RoleErrors.OperationFailed;
            }
        }

        public async Task<Result> UpdateRole(UpdateRoleRequest UpdatedRole)
        {        
            try
            {
                var role = await roleRepository.GetByIdAsync(UpdatedRole.RolesId);

                if (role == null) // Check for null role before accessing properties
                {
                    return Result.Failure(RoleErrors.RoleNotFound);
                }

                role.RoleName = UpdatedRole.RoleName ?? role.RoleName;
                role.RoleDescription = UpdatedRole.RoleDescription ?? role.RoleDescription;
                role.IsActive = UpdatedRole.IsActive ?? role.IsActive;

                await roleRepository.UpdateAsync(role);
                await roleRepository.SaveChangesAsync();
                return Result.Success();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error occurred while updating role {RoleId}.", UpdatedRole.RolesId);
                return Result.Failure(RoleErrors.OperationFailed);
            }
        }

        public async Task<Result<List<RoleResponse>>> GetRolesForUserAsync(List<UserRoleResponse> userRoles)
        {
            try
            {
                if (userRoles == null || userRoles.Count == 0)
                {
                    return Result<List<RoleResponse>>.Success(new List<RoleResponse>());
                }

                var roleIds = userRoles
                    .Select(r => r.RoleId)
                    .Distinct()
                    .ToList();
                
                var roles = await roleRepository.GetAllByIdAsync(roleIds);
                
                var mapped = roles.Select(r => new RoleResponse
                {
                    RolesId = r.RolesId,
                    RoleName = r.RoleName,
                    RoleDescription = r.RoleDescription,
                    IsActive = r.IsActive,
                    CreatedAt = r.CreatedAt
                }).ToList();

                return Result<List<RoleResponse>>.Success(mapped);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error occurred while getting roles for user.");
                return RoleErrors.OperationFailed;
            }
        }
    }
}



