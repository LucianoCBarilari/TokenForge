using Application.Feature.UserRoleFeature;
using Application.Feature.UserRoleFeature.UserRoleDto;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Web.Controllers;

[Authorize]
[ApiController]
[Route("api/user-roles")]
public class UserRoleController(
    IUserRoleService userRoleService,
    ILogger<UserRoleController> logger
    ) : ApiControllerBase
{


    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetById(Guid id)
    {

        var result = await userRoleService.GetUserRoleByIdAsync(id);

        if (result.IsFailure)
        {
            logger.LogWarning("Failed to retrieve user role with ID {Id}: {Error}", id, result.Error.Message);
            return HandleFailure(result);
        }
        return ToActionResult(result);
    }

    [HttpPost]
    public async Task<IActionResult> AssignRoleToUser([FromBody] AssignRoleRequest assignRoleRequest)
    {

        var result = await userRoleService.AssignRoleToUserAsync(assignRoleRequest);

        if (result.IsFailure)
        {
            logger.LogWarning("Failed to assign role {RoleId} to user {UserId}: {Error}", assignRoleRequest.RoleId, assignRoleRequest.UserId, result.Error.Message);
            return HandleFailure(result);
        }
        return Ok(new { message = "Role assigned successfully." });
    }

    [HttpPost("revoke")]
    public async Task<IActionResult> RevokeRoleForUser([FromBody] RevokeRoleRequest revokeRoleRequest)
    {
        var result = await userRoleService.RevokeRole(revokeRoleRequest);

        if (result.IsFailure)
        {
            logger.LogWarning("Failed to revoke role {RoleId} from user {UserId}: {Error}", revokeRoleRequest.RoleId, revokeRoleRequest.UserId, result.Error.Message);
            return HandleFailure(result);
        }
        return Ok(new { message = "Role revoked successfully." });
    }

    [HttpGet("~/api/users/{userId:guid}/roles")]
    public async Task<IActionResult> GetRolesForUser(Guid userId)
    {
        var result = await userRoleService.GetRolesByUserIdAsync(userId);

        if (result.IsFailure)
        {
            logger.LogWarning("Failed to retrieve roles for user {UserId}: {Error}", userId, result.Error.Message);
            return HandleFailure(result);
        }
        return ToActionResult(result);
    }

    [HttpGet("~/api/roles/{roleId:guid}/users")]
    public async Task<IActionResult> GetUsersForRole(Guid roleId)
    {
        var result = await userRoleService.GetAllUsersFromRole(roleId);

        if (result.IsFailure)
        {
            logger.LogWarning("Failed to retrieve users for role {RoleId}: {Error}", roleId, result.Error.Message);
            return HandleFailure(result);
        }
        return ToActionResult(result);
    }
}
