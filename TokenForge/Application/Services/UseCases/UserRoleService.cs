
using Microsoft.Extensions.Logging;
using TokenForge.Application.Dtos.RoleDto;
using TokenForge.Application.Dtos.UserDto;
using TokenForge.Application.Dtos.UserRoleDto;
using TokenForge.Domain.Entities;
using TokenForge.Domain.Errors;
using TokenForge.Domain.Interfaces;
using TokenForge.Domain.Shared;

namespace TokenForge.Application.Services.UseCases
{
    public class UserRoleService(
        IUserRoleRepository userRoleRepository,
        IUserRepository userRepository,
        IRoleRepository roleRepository, // Injected IRoleRepository
        ILogger<UserRoleService> logger
        ) : IUserRoleService
    {
        private readonly IUserRoleRepository _userRoleRepository = userRoleRepository;
        private readonly IUserRepository _userRepository = userRepository;
        private readonly IRoleRepository _roleRepository = roleRepository; // Initialized IRoleRepository
        private readonly ILogger<UserRoleService> _logger = logger;

        public async Task<Result> AssignRoleToUserAsync(AssignRoleRequest assignRole)
        {
            try
            {
                var currentUser = await _userRepository.GetByIdAsync(assignRole.UserId);
                if (currentUser == null)
                {
                    return UserRoleErrors.UserNotFound;
                }

                var role = await _roleRepository.GetByIdAsync(assignRole.RoleId);
                if (role == null)
                {
                    return UserRoleErrors.RoleNotFound;
                }

                var existingAssignment = await _userRoleRepository.FindByUserIdAndRoleIdAsync(assignRole.UserId, assignRole.RoleId);
                if (existingAssignment != null)
                {
                    if (existingAssignment.IsActive)
                    {
                        return UserRoleErrors.UserAlreadyInRole;
                    }
                    else
                    {
                        // Re-activate the existing role assignment
                        existingAssignment.IsActive = true;
                        existingAssignment.DeactivatedAt = null;
                        existingAssignment.DeactivatedReason = null;
                        await _userRoleRepository.UpdateAsync(existingAssignment);
                    }
                }
                else
                {
                    // Create a new assignment
                    var userRole = new UserRole
                    {
                        UserId = assignRole.UserId,
                        RoleId = assignRole.RoleId,
                        AssignedAt = DateTime.UtcNow,
                        IsActive = true
                    };
                    await _userRoleRepository.AddAsync(userRole);
                }

                await _userRoleRepository.SaveChangesAsync();
                return Result.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error assigning role {RoleId} to user {UserId}", assignRole.RoleId, assignRole.UserId);
                return UserRoleErrors.OperationFailed;
            }
        }

        public Task<Result<List<UserRoleResponse>>> GetAllUserRolesAsync()
        {
            throw new NotImplementedException();
        }

        public async Task<Result<UserRoleResponse>> GetUserRoleByIdAsync(Guid userRoleId)
        {
            try
            {
                var userRole = await _userRoleRepository.GetByIdAsync(userRoleId);
                if (userRole == null)
                {
                    return UserRoleErrors.UserRoleNotFound;
                }

                var user = await _userRepository.GetByIdAsync(userRole.UserId);

                var userRoleDto = new UserRoleResponse
                {
                    UserRoleId = userRole.UserRoleId,
                    UserId = userRole.UserId,
                    UserAccount = user?.UserAccount ?? string.Empty,
                    RoleId = userRole.RoleId,
                    RoleName = userRole.Role?.RoleName ?? string.Empty,
                    AssignedAt = userRole.AssignedAt,
                    IsActive = userRole.IsActive,
                    DeactivatedAt = userRole.DeactivatedAt,
                    DeactivatedReason = userRole.DeactivatedReason
                };

                return userRoleDto;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting user role by ID {UserRoleId}", userRoleId);
                return UserRoleErrors.OperationFailed;
            }
        }

        public async Task<Result> RevokeRole(RevokeRoleRequest RoleToRevoke)
        {
            try
            {
                var userRole = await _userRoleRepository.FindByUserIdAndRoleIdAsync(RoleToRevoke.UserId, RoleToRevoke.RoleId);

                if (userRole == null || !userRole.IsActive)
                {
                    return UserRoleErrors.ActiveAssignmentNotFound;
                }

                userRole.IsActive = false;
                userRole.DeactivatedAt = DateTime.UtcNow;
                userRole.DeactivatedReason = RoleToRevoke.Reason;

                await _userRoleRepository.UpdateAsync(userRole);
                await _userRoleRepository.SaveChangesAsync();
                return Result.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error revoking role {RoleId} from user {UserId}", RoleToRevoke.RoleId, RoleToRevoke.UserId);
                return UserRoleErrors.OperationFailed;
            }
        }

        public async Task<Result<List<UserRoleResponse>>> GetRolesByUserIdAsync(Guid userId)
        {
            try
            {
                var userRoles = await _userRoleRepository.GetRolesByUserIdAsync(userId) ?? new List<UserRole>();

                // This mapping is likely incomplete as it doesn't fetch User/Role names.
                // For now, it correctly maps the available data.
                var userRoleDtos = userRoles.Select(ur => new UserRoleResponse
                {
                    UserRoleId = ur.UserRoleId,
                    UserId = ur.UserId,
                    RoleId = ur.RoleId,
                    RoleName = ur.Role?.RoleName ?? string.Empty, // Assuming Role is loaded
                    AssignedAt = ur.AssignedAt,
                    IsActive = ur.IsActive,
                    DeactivatedAt = ur.DeactivatedAt,
                    DeactivatedReason = ur.DeactivatedReason
                }).ToList();
                return Result<List<UserRoleResponse>>.Success(userRoleDtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting roles for user {UserId}", userId);
                return UserRoleErrors.OperationFailed;
            }
        }

        public async Task<Result<List<UserResponse>>> GetAllUsersFromRole(Guid roleId)
        {
            try
            {
                var role = await _roleRepository.GetByIdAsync(roleId);
                if (role == null)
                {
                    return UserRoleErrors.RoleNotFound;
                }

                var users = await _userRoleRepository.GetUsersByRoleIdAsync(roleId) ?? new List<User>();

                // It's not an error if no users are found, just return an empty list.
                var userDtos = users.Select(u => new UserResponse
                {
                    UserId = u.UsersId,
                    UserAccount = u.UserAccount,
                    Email = u.Email
                }).ToList();

                return Result<List<UserResponse>>.Success(userDtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting users for role {RoleId}", roleId);
                return UserRoleErrors.OperationFailed;
            }
        }
    }
}



