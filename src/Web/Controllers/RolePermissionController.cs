using Application.Feature.RolePermissionFeature;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Web.Controllers;

[Authorize]
[ApiController]
[Route("api/role-permissions")]
public class RolePermissionController(
    IRolePermissionService rolePermissionService,
    ILogger<RolePermissionController> logger) : ApiControllerBase
{
    [HttpPost("assign")]
    public async Task<IActionResult> AssignPermission([FromBody] AssignRolePermissionInputDto input)
    {
        var result = await rolePermissionService.AssignPermissionToRoleAsync(input, HttpContext.RequestAborted);
        if (result.IsFailure)
        {
            logger.LogWarning("Failed to assign permission {PermissionId} to role {RoleId}: {Error}", input.PermissionId, input.RoleId, result.Error.Message);
            return HandleFailure(result);
        }

        return Ok(new { message = "Permission assigned to role successfully." });
    }

    [HttpPost("revoke")]
    public async Task<IActionResult> RevokePermission([FromBody] RevokeRolePermissionInputDto input)
    {
        var result = await rolePermissionService.RevokePermissionFromRoleAsync(input, HttpContext.RequestAborted);
        if (result.IsFailure)
        {
            logger.LogWarning("Failed to revoke permission {PermissionId} from role {RoleId}: {Error}", input.PermissionId, input.RoleId, result.Error.Message);
            return HandleFailure(result);
        }

        return Ok(new { message = "Permission revoked from role successfully." });
    }

    [HttpPut("sync/{roleId:guid}")]
    public async Task<IActionResult> SyncRolePermissions(Guid roleId, [FromBody] SyncRolePermissionsInputDto input)
    {
        input.RoleId = roleId;
        var result = await rolePermissionService.SyncRolePermissionsAsync(input, HttpContext.RequestAborted);
        if (result.IsFailure)
        {
            logger.LogWarning("Failed to sync permissions for role {RoleId}: {Error}", roleId, result.Error.Message);
            return HandleFailure(result);
        }

        return Ok(new { message = "Role permissions synchronized successfully." });
    }

    [HttpGet("roles/{roleId:guid}/permissions")]
    public async Task<IActionResult> GetPermissionsByRole(Guid roleId)
    {
        var result = await rolePermissionService.GetPermissionsByRoleAsync(roleId, HttpContext.RequestAborted);
        if (result.IsFailure)
        {
            logger.LogWarning("Failed to get permissions for role {RoleId}: {Error}", roleId, result.Error.Message);
            return HandleFailure(result);
        }

        return ToActionResult(result);
    }

    [HttpGet("permissions/{permissionId:guid}/roles")]
    public async Task<IActionResult> GetRolesByPermission(Guid permissionId)
    {
        var result = await rolePermissionService.GetRolesByPermissionAsync(permissionId, HttpContext.RequestAborted);
        if (result.IsFailure)
        {
            logger.LogWarning("Failed to get roles for permission {PermissionId}: {Error}", permissionId, result.Error.Message);
            return HandleFailure(result);
        }

        return ToActionResult(result);
    }
}
