using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TokenForge.Application.Dtos.RoleDto;
using TokenForge.Domain.Interfaces;
using TokenForge.Domain.Shared; // For Result and Error
using TokenForge.Domain.Errors; // For RoleErrors
using Microsoft.Extensions.Logging; // For ILogger
using Microsoft.AspNetCore.Http;
using TokenForge.WebApi.Models;

namespace TokenForge.WebApi.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/roles")]
    public class RoleController(
        IRoleService roleService,
        ILogger<RoleController> logger // Inject ILogger
        ) : Controller
    {
        
        private readonly IRoleService _roleService = roleService;
        private readonly ILogger<RoleController> _logger = logger; // Initialize Logger

        [HttpGet]
        public async Task<IActionResult> GetAllRoles()
        {
            _logger.LogInformation("Attempting to retrieve all roles.");
            var result = await _roleService.GetAllRoles();

            if (result.IsFailure)
            {
                _logger.LogWarning("Failed to retrieve all roles: {Error}", result.Error.Message);
                return HandleFailure(result.Error);
            }
            
            _logger.LogInformation("Successfully retrieved all roles.");
            return OkResponse(result.Value);
        }

        [HttpGet("{roleId:guid}")]
        public async Task<IActionResult> GetRoleById(Guid roleId)
        {
            _logger.LogInformation("Attempting to retrieve role with ID {RoleId}.", roleId);
            var result = await _roleService.GetRoleById(roleId);

            if (result.IsFailure)
            {
                _logger.LogWarning("Failed to retrieve role with ID {RoleId}: {Error}", roleId, result.Error.Message);
                return HandleFailure(result.Error);
            }

            _logger.LogInformation("Successfully retrieved role with ID {RoleId}.", roleId);
            return OkResponse(result.Value);
        }

        [HttpPut("{roleId:guid}")]
        public async Task<IActionResult> UpdateRole(Guid roleId, [FromBody] UpdateRoleRequest updateRoleRequest)
        {        
            updateRoleRequest.RolesId = roleId;
            _logger.LogInformation("Attempting to update role with ID {RoleId}.", updateRoleRequest.RolesId);
            var result = await _roleService.UpdateRole(updateRoleRequest);

            if (result.IsFailure)
            {
                _logger.LogWarning("Failed to update role with ID {RoleId}: {Error}", updateRoleRequest.RolesId, result.Error.Message);
                return HandleFailure(result.Error);
            }

            _logger.LogInformation("Role with ID {RoleId} updated successfully.", updateRoleRequest.RolesId);
            return OkResponse(message: "Role updated successfully.");
        }

        // Helper method to convert Error to IActionResult
        private IActionResult HandleFailure(Error error)
        {
            return error switch
            {
                { Code: var code } when code == RoleErrors.RoleNotFound.Code => FailResponse(error, StatusCodes.Status404NotFound),
                _ => FailResponse(error, StatusCodes.Status500InternalServerError) // Default for generic OperationFailed or unhandled errors, including RoleErrors.OperationFailed
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
}



