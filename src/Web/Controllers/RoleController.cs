using Application.Feature.RoleFeature;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Web.Controllers;

[Authorize]
[ApiController]
[Route("api/roles")]
public class RoleController(
    IRoleService roleService,
    ILogger<RoleController> logger
    ) : ApiControllerBase
{

    [HttpGet]
    public async Task<IActionResult> GetAllRoles()
    {
        logger.LogInformation("Attempting to retrieve all roles.");
        var result = await roleService.GetAllRoles();

        if (result.IsFailure)
        {
            logger.LogWarning("Failed to retrieve all roles: {Error}", result.Error.Message);
            return HandleFailure(result);
        }

        logger.LogInformation("Successfully retrieved all roles.");
        return ToActionResult(result);
    }

    [HttpGet("{roleId:guid}")]
    public async Task<IActionResult> GetRoleById(Guid roleId)
    {
        var result = await roleService.GetRoleById(roleId);

        if (result.IsFailure)
        {
            logger.LogWarning("Failed to retrieve role with ID {RoleId}: {Error}", roleId, result.Error.Message);
            return HandleFailure(result);
        }

        logger.LogInformation("Successfully retrieved role with ID {RoleId}.", roleId);
        return ToActionResult(result);
    }

    [HttpPut("{roleId:guid}")]
    public async Task<IActionResult> UpdateRole(Guid roleId, [FromBody] RoleInputDto updateRoleRequest)
    {
        updateRoleRequest.RolesId = roleId;

        var result = await roleService.UpdateRole(updateRoleRequest);

        if (result.IsFailure)
        {
            logger.LogWarning("Failed to update role with ID {RoleId}: {Error}", updateRoleRequest.RolesId, result.Error.Message);
            return HandleFailure(result);
        }
        return Ok(new { message = "Role updated successfully." });
    }
}



