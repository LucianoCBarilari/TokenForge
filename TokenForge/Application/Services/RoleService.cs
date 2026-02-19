using TokenForge.Application.Dtos.RoleDto;
using TokenForge.Application.Dtos.UserRoleDto;
using TokenForge.Infrastructure.DataAccess;

namespace TokenForge.Application.Services;

    public class RoleService(
        TokenForgeContext _dbContext,
        ILogger<RoleService> logger
        ) : IRoleService
    {
        public async Task<Result<List<RoleResponse>>> GetAllRoles() 
        {
            try
            {
                var roles = await _dbContext.Roles.ToListAsync();
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
                return Result<List<RoleResponse>>.Failure(RoleErrors.OperationFailed);
            }
        }

        public async Task<Result<RoleResponse>> GetRoleById(Guid roleId) 
        {
            try
            {
                var role = await _dbContext.Roles.FindAsync(roleId);
                if (role == null)
                {
                    return Result<RoleResponse>.Failure(RoleErrors.RoleNotFound);
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
                return Result<RoleResponse>.Failure(RoleErrors.OperationFailed);
            }
        }

        public async Task<Result> UpdateRole(UpdateRoleRequest updatedRole)
        {        
            try
            {
                var role = await _dbContext.Roles.FindAsync(updatedRole.RolesId);

                if (role == null)
                {
                    return Result.Failure(RoleErrors.RoleNotFound);
                }

                role.RoleName = updatedRole.RoleName ?? role.RoleName;
                role.RoleDescription = updatedRole.RoleDescription ?? role.RoleDescription;
                role.IsActive = updatedRole.IsActive ?? role.IsActive;

                _dbContext.Roles.Update(role);
                await _dbContext.SaveChangesAsync();
                return Result.Success();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error occurred while updating role {RoleId}.", updatedRole.RolesId);
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
                
                var roles = await _dbContext.Roles
                                 .Where(role => roleIds.Contains(role.RolesId))
                                 .ToListAsync();
                
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
                return Result<List<RoleResponse>>.Failure(RoleErrors.OperationFailed);
            }
        }
    }