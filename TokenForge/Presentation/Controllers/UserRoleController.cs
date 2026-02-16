

using TokenForge.Application.Dtos.RoleDto;
using TokenForge.Application.Dtos.UserRoleDto;

namespace TokenForge.Presentation.Controllers;

    [Authorize]
    [ApiController]
    [Route("api/user-roles")]
    public class UserRoleController(
        IUserRoleService userRoleService,
        ILogger<UserRoleController> logger
        ) : ControllerBase
    { 

        
        [HttpGet("{id:guid}")]
        public async Task<IActionResult> GetById(Guid id)
        {
            
            var result = await userRoleService.GetUserRoleByIdAsync(id);
            
            if (result.IsFailure)
            {
                logger.LogWarning("Failed to retrieve user role with ID {Id}: {Error}", id, result.Error.Message);
                return HandleFailure(result.Error);
            }
            return OkResponse(result.Value);
        }

        [HttpPost]
        public async Task<IActionResult> AssignRoleToUser([FromBody] AssignRoleRequest assignRoleRequest)
        {
            
            var result = await userRoleService.AssignRoleToUserAsync(assignRoleRequest);

            if (result.IsFailure)
            {
                logger.LogWarning("Failed to assign role {RoleId} to user {UserId}: {Error}", assignRoleRequest.RoleId, assignRoleRequest.UserId, result.Error.Message);
                return HandleFailure(result.Error);
            }
            return OkResponse(message: "Role assigned successfully.");
        }

        [HttpPost("revoke")]
        public async Task<IActionResult> RevokeRoleForUser([FromBody] RevokeRoleRequest revokeRoleRequest)
        {           
            var result = await userRoleService.RevokeRole(revokeRoleRequest);

            if (result.IsFailure)
            {
                logger.LogWarning("Failed to revoke role {RoleId} from user {UserId}: {Error}", revokeRoleRequest.RoleId, revokeRoleRequest.UserId, result.Error.Message);
                return HandleFailure(result.Error);
            }            
            return OkResponse(message: "Role revoked successfully.");
        }

        [HttpGet("~/api/users/{userId:guid}/roles")]
        public async Task<IActionResult> GetRolesForUser(Guid userId)
        {           
            var result = await userRoleService.GetRolesByUserIdAsync(userId);

            if (result.IsFailure)
            {
                logger.LogWarning("Failed to retrieve roles for user {UserId}: {Error}", userId, result.Error.Message);
                return HandleFailure(result.Error);
            }            
            return OkResponse(result.Value);
        }

        [HttpGet("~/api/roles/{roleId:guid}/users")]
        public async Task<IActionResult> GetUsersForRole(Guid roleId)
        {            
            var result = await userRoleService.GetAllUsersFromRole(roleId);

            if (result.IsFailure)
            {
                logger.LogWarning("Failed to retrieve users for role {RoleId}: {Error}", roleId, result.Error.Message);
                return HandleFailure(result.Error);
            }
            return OkResponse(result.Value);
        }

        private IActionResult HandleFailure(Error error)
        {
            return error switch
            {
                { Code: var code } when code == UserRoleErrors.UserNotFound.Code => FailResponse(error, StatusCodes.Status404NotFound),
                { Code: var code } when code == UserRoleErrors.RoleNotFound.Code => FailResponse(error, StatusCodes.Status404NotFound),
                { Code: var code } when code == UserRoleErrors.UserAlreadyInRole.Code => FailResponse(error, StatusCodes.Status409Conflict),
                { Code: var code } when code == UserRoleErrors.ActiveAssignmentNotFound.Code => FailResponse(error, StatusCodes.Status404NotFound),
                { Code: var code } when code == UserRoleErrors.UserRoleNotFound.Code => FailResponse(error, StatusCodes.Status404NotFound),
                _ => FailResponse(error, StatusCodes.Status500InternalServerError)
            };
        }

        private IActionResult OkResponse(object? result = null, string? message = null, int statusCode = StatusCodes.Status200OK)
        {
            var response = ApiResponse.SuccessResponse(result, message, statusCode, HttpContext?.TraceIdentifier);
            return StatusCode(statusCode, response);
        }

        private IActionResult FailResponse(Error error, int statusCode, string? message = null)
        {
            var response = ApiResponse.FailureResponse(new[] { error }, message ?? error.Message, statusCode, HttpContext?.TraceIdentifier);
            return StatusCode(statusCode, response);
        }
    }