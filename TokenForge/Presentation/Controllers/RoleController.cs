using TokenForge.Application.Dtos.RoleDto;

namespace TokenForge.Presentation.Controllers;

    [Authorize]
    [ApiController]
    [Route("api/roles")]
    public class RoleController(
        IRoleService roleService,
        ILogger<RoleController> logger 
        ) : ControllerBase
{

        [HttpGet]
        public async Task<IActionResult> GetAllRoles()
        {
            logger.LogInformation("Attempting to retrieve all roles.");
            var result = await roleService.GetAllRoles();

            if (result.IsFailure)
            {
                logger.LogWarning("Failed to retrieve all roles: {Error}", result.Error.Message);
                return HandleFailure(result.Error);
            }
            
            logger.LogInformation("Successfully retrieved all roles.");
            return OkResponse(result.Value);
        }

        [HttpGet("{roleId:guid}")]
        public async Task<IActionResult> GetRoleById(Guid roleId)
        {
            var result = await roleService.GetRoleById(roleId);

            if (result.IsFailure)
            {
                logger.LogWarning("Failed to retrieve role with ID {RoleId}: {Error}", roleId, result.Error.Message);
                return HandleFailure(result.Error);
            }

            logger.LogInformation("Successfully retrieved role with ID {RoleId}.", roleId);
            return OkResponse(result.Value);
        }

        [HttpPut("{roleId:guid}")]
        public async Task<IActionResult> UpdateRole(Guid roleId, [FromBody] UpdateRoleRequest updateRoleRequest)
        {        
            updateRoleRequest.RolesId = roleId;
            
            var result = await roleService.UpdateRole(updateRoleRequest);

            if (result.IsFailure)
            {
                logger.LogWarning("Failed to update role with ID {RoleId}: {Error}", updateRoleRequest.RolesId, result.Error.Message);
                return HandleFailure(result.Error);
            }
            return OkResponse(message: "Role updated successfully.");
        }
        private IActionResult HandleFailure(Error error)
        {
            return error switch
            {
                { Code: var code } when code == RoleErrors.RoleNotFound.Code => FailResponse(error, StatusCodes.Status404NotFound),
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



