using Microsoft.Extensions.Logging;
using TokenForge.Application.Dtos.RoleDto;
using TokenForge.Application.Dtos.UserRoleDto;
using TokenForge.Domain.Entities;
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
        private readonly IRoleRepository _roleRepository = roleRepository;
        private readonly ILogger<RoleService> _logger = logger;

        public async Task<Result<List<RoleResponse>>> GetAllRoles() 
        {
            try
            {
                var roles = await _roleRepository.GetAllAsync() ?? new List<Role>();
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
                _logger.LogError(ex, "Error occurred while getting all roles.");
                return RoleErrors.OperationFailed;
            }
        }

        public async Task<Result<RoleResponse>> GetRoleById(Guid roleId) 
        {
            try
            {
                var role = await _roleRepository.GetByIdAsync(roleId);
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
                _logger.LogError(ex, "Error occurred while getting role by ID {RoleId}.", roleId);
                return RoleErrors.OperationFailed;
            }
        }

        public async Task<Result> UpdateRole(UpdateRoleRequest updatedRole)
        {        
            try
            {
                var role = await _roleRepository.GetByIdAsync(updatedRole.RolesId);

                if (role == null) // Check for null role before accessing properties
                {
                    return RoleErrors.RoleNotFound;
                }

                role.RoleName = updatedRole.RoleName ?? role.RoleName;
                role.RoleDescription = updatedRole.RoleDescription ?? role.RoleDescription;
                role.IsActive = updatedRole.IsActive ?? role.IsActive;

                await _roleRepository.UpdateAsync(role);
                await _roleRepository.SaveChangesAsync();
                return Result.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while updating role {RoleId}.", updatedRole.RolesId);
                return RoleErrors.OperationFailed;
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
                
                var roles = await _roleRepository.GetAllByIdAsync(roleIds);
                
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
                _logger.LogError(ex, "Error occurred while getting roles for user.");
                return RoleErrors.OperationFailed;
            }
        }
    }
}



