using Application.Constants;
using Application.Feature.PermissionFeature;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Web.Controllers;

[Authorize]
[ApiController]
[Route("api/permissions")]
public class PermissionController(
    IPermissionService permissionService,
    ILogger<PermissionController> logger) : ApiControllerBase
{
    [Authorize(Policy = PermissionCodes.PermissionsCreate)]
    [HttpPost]
    public async Task<IActionResult> CreatePermission([FromBody] PermissionCreateInputDto input)
    {
        var result = await permissionService.CreatePermissionAsync(input, HttpContext.RequestAborted);
        if (result.IsFailure)
        {
            logger.LogWarning("Failed to create permission {PermissionCode}: {Error}", input.PermissionCode, result.Error.Message);
            return HandleFailure(result);
        }

        return ToActionResult(result);
    }

    [Authorize(Policy = PermissionCodes.PermissionsUpdate)]
    [HttpPut("{permissionId:guid}")]
    public async Task<IActionResult> UpdatePermission(Guid permissionId, [FromBody] PermissionUpdateInputDto input)
    {
        input.PermissionId = permissionId;
        var result = await permissionService.UpdatePermissionAsync(input, HttpContext.RequestAborted);
        if (result.IsFailure)
        {
            logger.LogWarning("Failed to update permission {PermissionId}: {Error}", permissionId, result.Error.Message);
            return HandleFailure(result);
        }

        return Ok(new { message = "Permission updated successfully." });
    }

    [Authorize(Policy = PermissionCodes.PermissionsDeactivate)]
    [HttpPost("{permissionId:guid}/deactivate")]
    public async Task<IActionResult> DeactivatePermission(Guid permissionId)
    {
        var result = await permissionService.DeactivatePermissionAsync(permissionId, HttpContext.RequestAborted);
        if (result.IsFailure)
        {
            logger.LogWarning("Failed to deactivate permission {PermissionId}: {Error}", permissionId, result.Error.Message);
            return HandleFailure(result);
        }

        return Ok(new { message = "Permission deactivated successfully." });
    }

    [Authorize(Policy = PermissionCodes.PermissionsActivate)]
    [HttpPost("{permissionId:guid}/reactivate")]
    public async Task<IActionResult> ReactivatePermission(Guid permissionId)
    {
        var result = await permissionService.ReactivatePermissionAsync(permissionId, HttpContext.RequestAborted);
        if (result.IsFailure)
        {
            logger.LogWarning("Failed to reactivate permission {PermissionId}: {Error}", permissionId, result.Error.Message);
            return HandleFailure(result);
        }

        return Ok(new { message = "Permission reactivated successfully." });
    }

    [Authorize(Policy = PermissionCodes.PermissionsRead)]
    [HttpGet]
    public async Task<IActionResult> GetAllPermissions()
    {
        var result = await permissionService.GetAllPermissionsAsync(HttpContext.RequestAborted);
        if (result.IsFailure)
        {
            logger.LogWarning("Failed to get all permissions: {Error}", result.Error.Message);
            return HandleFailure(result);
        }

        return ToActionResult(result);
    }

    [Authorize(Policy = PermissionCodes.PermissionsRead)]
    [HttpGet("active")]
    public async Task<IActionResult> GetActivePermissions()
    {
        var result = await permissionService.GetActivePermissionsAsync(HttpContext.RequestAborted);
        if (result.IsFailure)
        {
            logger.LogWarning("Failed to get active permissions: {Error}", result.Error.Message);
            return HandleFailure(result);
        }

        return ToActionResult(result);
    }

    [Authorize(Policy = PermissionCodes.PermissionsRead)]
    [HttpGet("{permissionId:guid}")]
    public async Task<IActionResult> GetPermissionById(Guid permissionId)
    {
        var result = await permissionService.GetPermissionByIdAsync(permissionId, HttpContext.RequestAborted);
        if (result.IsFailure)
        {
            logger.LogWarning("Failed to get permission {PermissionId}: {Error}", permissionId, result.Error.Message);
            return HandleFailure(result);
        }

        return ToActionResult(result);
    }

    [Authorize(Policy = PermissionCodes.PermissionsRead)]
    [HttpGet("code/{permissionCode}")]
    public async Task<IActionResult> GetPermissionByCode(string permissionCode)
    {
        var result = await permissionService.GetPermissionByCodeAsync(permissionCode, HttpContext.RequestAborted);
        if (result.IsFailure)
        {
            logger.LogWarning("Failed to get permission by code {PermissionCode}: {Error}", permissionCode, result.Error.Message);
            return HandleFailure(result);
        }

        return ToActionResult(result);
    }
}
