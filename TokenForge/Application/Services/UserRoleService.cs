using TokenForge.Application.Dtos.RoleDto;
using TokenForge.Application.Dtos.UserDto;
using TokenForge.Application.Dtos.UserRoleDto;
using TokenForge.Domain.Entities;
using TokenForge.Infrastructure.DataAccess;

namespace TokenForge.Application.Services;

    public class UserRoleService(
        TokenForgeContext _dbContext,
        ILogger<UserRoleService> logger
        ) : IUserRoleService
    {

        public async Task<Result> AssignRoleToUserAsync(AssignRoleRequest assignRole)
        {
            try
            {
                var currentUser = await _dbContext.Users.FindAsync(assignRole.UserId);
                if (currentUser == null)
                {
                    return Result.Failure(UserRoleErrors.UserNotFound);
                }

                var role = await _dbContext.Roles.FindAsync(assignRole.RoleId);
                if (role == null)
                {
                    return Result.Failure(UserRoleErrors.RoleNotFound);
                }

                var existingAssignment = await _dbContext.UserRoles
                                                      .FirstOrDefaultAsync(ur => ur.UserId == assignRole.UserId && ur.RoleId == assignRole.RoleId);
                  
                if (existingAssignment != null)
                {
                    if (existingAssignment.IsActive)
                    {
                        return Result.Failure(UserRoleErrors.UserAlreadyInRole);
                    }
                    else
                    {

                        existingAssignment.IsActive = true;
                        existingAssignment.DeactivatedAt = null;
                        existingAssignment.DeactivatedReason = null;
                        _dbContext.UserRoles.Update(existingAssignment);
                    }
                }
                else
                {                    
                    var userRole = new UserRole
                    {
                        UserId = assignRole.UserId,
                        RoleId = assignRole.RoleId,
                        AssignedAt = DateTime.UtcNow,
                        IsActive = true
                    };
                    await _dbContext.UserRoles.AddAsync(userRole);
                }

                await _dbContext.SaveChangesAsync();
                return Result.Success();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error assigning role {RoleId} to user {UserId}", assignRole.RoleId, assignRole.UserId);
                return Result.Failure(UserRoleErrors.OperationFailed);
            }
        }

        public async Task<Result<UserRoleResponse>> GetUserRoleByIdAsync(Guid userRoleId)
        {
            try
            {
                var userRole = await _dbContext.UserRoles
                                 .Include(ur => ur.Role)
                                 .FirstOrDefaultAsync(ur => ur.UserRoleId == userRoleId);

                if (userRole == null)
                {
                    return Result<UserRoleResponse>.Failure(UserRoleErrors.UserRoleNotFound);
                }

                var user = await _dbContext.Users.FindAsync(userRole.UserId);

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
                logger.LogError(ex, "Error getting user role by ID {UserRoleId}", userRoleId);
                return Result<UserRoleResponse>.Failure(UserRoleErrors.OperationFailed);
            }
        }

        public async Task<Result> RevokeRole(RevokeRoleRequest RoleToRevoke)
        {
            try
            {
                var userRole = await _dbContext.UserRoles
                                 .FirstOrDefaultAsync(ur => ur.UserId == RoleToRevoke.UserId && ur.RoleId == RoleToRevoke.RoleId);

                if (userRole == null || !userRole.IsActive)
                {
                    return Result.Failure(UserRoleErrors.ActiveAssignmentNotFound);
                }

                userRole.IsActive = false;
                userRole.DeactivatedAt = DateTime.UtcNow;
                userRole.DeactivatedReason = RoleToRevoke.Reason;

                _dbContext.UserRoles.Update(userRole);
                await _dbContext.SaveChangesAsync();
                return Result.Success();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error revoking role {RoleId} from user {UserId}", RoleToRevoke.RoleId, RoleToRevoke.UserId);
                return Result.Failure(UserRoleErrors.OperationFailed);
            }
        }

        public async Task<Result<List<UserRoleResponse>>> GetRolesByUserIdAsync(Guid userId)
        {
            try
            {
                var userRoles = await _dbContext.UserRoles
                                 .Where(ur => ur.UserId == userId && ur.IsActive)
                                 .Include(ur => ur.Role)
                                 .ToListAsync();
 
                var userRoleDtos = userRoles.Select(ur => new UserRoleResponse
                {
                    UserRoleId = ur.UserRoleId,
                    UserId = ur.UserId,
                    RoleId = ur.RoleId,
                    RoleName = ur.Role?.RoleName ?? string.Empty, 
                    AssignedAt = ur.AssignedAt,
                    IsActive = ur.IsActive,
                    DeactivatedAt = ur.DeactivatedAt,
                    DeactivatedReason = ur.DeactivatedReason
                }).ToList();

                return Result<List<UserRoleResponse>>.Success(userRoleDtos);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error getting roles for user {UserId}", userId);
                return Result<List<UserRoleResponse>>.Failure(UserRoleErrors.OperationFailed);
            }
        }

        public async Task<Result<List<UserResponse>>> GetAllUsersFromRole(Guid roleId)
        {
            try
            {
                var role = await _dbContext.Roles.FindAsync(roleId);
                if (role == null)
                {
                    return Result<List<UserResponse>>.Failure(UserRoleErrors.RoleNotFound);
                }

                var users = await _dbContext.UserRoles
                                 .Where(ur => ur.RoleId == roleId && ur.IsActive)
                                 .Include(ur => ur.User)
                                 .Select(ur => ur.User!)
                                 .ToListAsync();
                
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
                logger.LogError(ex, "Error getting users for role {RoleId}", roleId);
                return Result<List<UserResponse>>.Failure(UserRoleErrors.OperationFailed);
            }
        }
    }