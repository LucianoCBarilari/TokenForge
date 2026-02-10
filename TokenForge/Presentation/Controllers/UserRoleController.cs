using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TokenForge.Application.Dtos.RoleDto;
using TokenForge.Application.Dtos.UserRoleDto;
using TokenForge.Domain.Interfaces;
using TokenForge.Domain.Shared;
using TokenForge.Domain.Errors;
using Microsoft.Extensions.Logging;
using System;
using Microsoft.AspNetCore.Http;
using TokenForge.WebApi.Models;

namespace TokenForge.WebApi.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/user-roles")]
    public class UserRoleController(
        IUserRoleService userRoleService,
        ILogger<UserRoleController> logger
        ) : ControllerBase
    {      
        private readonly IUserRoleService _userRoleService = userRoleService;
        private readonly ILogger<UserRoleController> _logger = logger;

        [HttpGet]
        public async Task<IActionResult> GetAllAsync()
        {
            _logger.LogInformation("Attempting to retrieve all user roles.");
            var result = await _userRoleService.GetAllUserRolesAsync();

            if (result.IsFailure)
            {
                _logger.LogWarning("Failed to retrieve all user roles: {Error}", result.Error.Message);
                return HandleFailure(result.Error);
            }

            _logger.LogInformation("Successfully retrieved all user roles.");
            return OkResponse(result.Value);
        }

        [HttpGet("{id:guid}")]
        public async Task<IActionResult> GetById(Guid id)
        {
            _logger.LogInformation("Attempting to retrieve user role with ID {Id}", id);
            var result = await _userRoleService.GetUserRoleByIdAsync(id);
            
            if (result.IsFailure)
            {
                _logger.LogWarning("Failed to retrieve user role with ID {Id}: {Error}", id, result.Error.Message);
                return HandleFailure(result.Error);
            }

            _logger.LogInformation("Successfully retrieved user role with ID {Id}", id);
            return OkResponse(result.Value);
        }

        [HttpPost]
        public async Task<IActionResult> AssignRoleToUser([FromBody] AssignRoleRequest assignRoleRequest)
        {
            _logger.LogInformation("Attempting to assign role {RoleId} to user {UserId}", assignRoleRequest.RoleId, assignRoleRequest.UserId);
            var result = await _userRoleService.AssignRoleToUserAsync(assignRoleRequest);

            if (result.IsFailure)
            {
                _logger.LogWarning("Failed to assign role {RoleId} to user {UserId}: {Error}", assignRoleRequest.RoleId, assignRoleRequest.UserId, result.Error.Message);
                return HandleFailure(result.Error);
            }

            _logger.LogInformation("Successfully assigned role {RoleId} to user {UserId}", assignRoleRequest.RoleId, assignRoleRequest.UserId);
            return OkResponse(message: "Role assigned successfully.");
        }

        [HttpPost("revoke")]
        public async Task<IActionResult> RevokeRoleForUser([FromBody] RevokeRoleRequest revokeRoleRequest)
        {
            _logger.LogInformation("Attempting to revoke role {RoleId} from user {UserId}", revokeRoleRequest.RoleId, revokeRoleRequest.UserId);
            var result = await _userRoleService.RevokeRole(revokeRoleRequest);

            if (result.IsFailure)
            {
                _logger.LogWarning("Failed to revoke role {RoleId} from user {UserId}: {Error}", revokeRoleRequest.RoleId, revokeRoleRequest.UserId, result.Error.Message);
                return HandleFailure(result.Error);
            }

            _logger.LogInformation("Successfully revoked role {RoleId} from user {UserId}", revokeRoleRequest.RoleId, revokeRoleRequest.UserId);
            return OkResponse(message: "Role revoked successfully.");
        }

        [HttpGet("~/api/users/{userId:guid}/roles")]
        public async Task<IActionResult> GetRolesForUser(Guid userId)
        {
            _logger.LogInformation("Attempting to retrieve roles for user {UserId}", userId);
            var result = await _userRoleService.GetRolesByUserIdAsync(userId);

            if (result.IsFailure)
            {
                _logger.LogWarning("Failed to retrieve roles for user {UserId}: {Error}", userId, result.Error.Message);
                return HandleFailure(result.Error);
            }

            _logger.LogInformation("Successfully retrieved roles for user {UserId}", userId);
            return OkResponse(result.Value);
        }

        [HttpGet("~/api/roles/{roleId:guid}/users")]
        public async Task<IActionResult> GetUsersForRole(Guid roleId)
        {
            _logger.LogInformation("Attempting to retrieve users for role {RoleId}", roleId);
            var result = await _userRoleService.GetAllUsersFromRole(roleId);

            if (result.IsFailure)
            {
                _logger.LogWarning("Failed to retrieve users for role {RoleId}: {Error}", roleId, result.Error.Message);
                return HandleFailure(result.Error);
            }

            _logger.LogInformation("Successfully retrieved users for role {RoleId}", roleId);
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
}


