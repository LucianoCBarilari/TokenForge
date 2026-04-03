using Application.Constants;
using Application.Feature.UserFeature;
using Application.Feature.UserFeature.UserDto;
using Domain.Errors;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Web.Controllers;

[Authorize]
[ApiController]
[Route("api/users")]
public class UserController(
    IUserService userService,
    ILogger<UserController> logger
    ) : ApiControllerBase
{

    [Authorize(Policy = PermissionCodes.UsersCreate)]
    [HttpPost]
    public async Task<IActionResult> CreateNewUser([FromBody] CreateUserRequest request)
    {
        var result = await userService.RegisterUser(request);

        if (result.IsFailure)
        {
            logger.LogWarning("Failed to create new user account for {UserAccount}: {Error}", request.UserAccount, result.Error.Message);
            return HandleFailure(result);
        }
        return Ok(new { message = "User account created successfully." });
    }

    [Authorize(Policy = PermissionCodes.UsersUpdateEmail)]
    [HttpPut("{userId:guid}/email")]
    public async Task<IActionResult> UpdateEmail(Guid userId, [FromBody] UpdateEmailRequest updateEmailDto)
    {
        updateEmailDto.UserId = userId;

        var result = await userService.UpdateEmail(updateEmailDto);

        if (result.IsFailure)
        {
            logger.LogWarning("Failed to update email for user {UserId}: {Error}", updateEmailDto.UserId, result.Error.Message);
            return HandleFailure(result);
        }
        return Ok(new { message = "Email updated successfully." });
    }

    [Authorize(Policy = PermissionCodes.UsersUpdateAccount)]
    [HttpPut("{userId:guid}/account")]
    public async Task<IActionResult> UpdateUserAccount(Guid userId, [FromBody] UpdateUserAccountRequest updateUserAccountDto)
    {
        updateUserAccountDto.UserId = userId;
        logger.LogInformation("Attempting to update account name for user {UserId} to {NewAccount}", updateUserAccountDto.UserId, updateUserAccountDto.NewAccount);
        var result = await userService.UpdateAccount(updateUserAccountDto);

        if (result.IsFailure)
        {
            logger.LogWarning("Failed to update account name for user {UserId}: {Error}", updateUserAccountDto.UserId, result.Error.Message);
            return HandleFailure(result);
        }
        return Ok(new { message = "User account updated successfully." });
    }

    [Authorize(Policy = PermissionCodes.UsersUpdatePassword)]
    [HttpPut("{userId:guid}/password")]
    public async Task<IActionResult> UpdatePassword(Guid userId, [FromBody] ChangePasswordRequest changePasswordRequest)
    {
        changePasswordRequest.UserId = userId;
        var result = await userService.UpdatePassword(changePasswordRequest);

        if (result.IsFailure)
        {
            logger.LogWarning("Failed to update password for user {UserId}: {Error}", changePasswordRequest.UserId, result.Error.Message);
            return HandleFailure(result);
        }
        return Ok(new { message = "Password updated successfully." });
    }

    [Authorize(Policy = PermissionCodes.UsersDisable)]
    [HttpPut("{userId:guid}/disable")]
    public async Task<IActionResult> DisableUser(Guid userId, [FromBody] DisableUserRequest disableUserRequest)
    {
        disableUserRequest.UserToDisable = userId;
        var result = await userService.DisableOneUser(disableUserRequest);

        if (result.IsFailure)
        {
            logger.LogWarning("Failed to disable user {UserId}: {Error}", disableUserRequest.UserToDisable, result.Error.Message);
            return HandleFailure(result);
        }
        return Ok(new { message = "User disabled successfully." });
    }

    [Authorize(Policy = PermissionCodes.UsersRead)]
    [HttpGet("{userId:guid}")]
    public async Task<IActionResult> GetUserById(Guid userId)
    {
        var result = await userService.UserById(userId);

        if (result.IsFailure)
        {
            logger.LogWarning("Failed to retrieve user with ID {UserId}: {Error}", userId, result.Error.Message);
            return HandleFailure(result);
        }
        return ToActionResult(result);
    }

    [Authorize(Policy = PermissionCodes.UsersRead)]
    [HttpGet("active")]
    public async Task<IActionResult> GetAllActiveUsers()
    {
        logger.LogInformation("Attempting to retrieve all active users.");
        var result = await userService.AllActiveUsers();

        if (result.IsFailure)
        {
            logger.LogWarning("Failed to retrieve all active users: {Error}", result.Error.Message);
            return HandleFailure(result);
        }

        logger.LogInformation("Successfully retrieved all active users.");
        return ToActionResult(result);
    }

    [Authorize(Policy = PermissionCodes.UsersReadRoles)]
    [HttpGet("active-with-roles")]
    public async Task<IActionResult> GetActiveUsersWithRoles()
    {
        logger.LogInformation("Attempting to retrieve all active users with roles.");
        var result = await userService.GetAllActiveRoles();

        if (result.IsFailure)
        {
            logger.LogWarning("Failed to retrieve all active users with roles: {Error}", result.Error.Message);
            return HandleFailure(result);
        }

        logger.LogInformation("Successfully retrieved all active users with roles.");
        return ToActionResult(result);
    }

    [Authorize(Policy = PermissionCodes.UsersReadRoles)]
    [HttpGet("{userId:guid}/with-roles")]
    public async Task<IActionResult> GetActiveUserWithRoles(Guid userId)
    {
        var result = await userService.GetActiveUserWithRoles(userId);

        if (result.IsFailure)
        {
            logger.LogWarning("Failed to retrieve active user with roles for ID {UserId}: {Error}", userId, result.Error.Message);
            return HandleFailure(result);
        }
        return ToActionResult(result);
    }

    protected override int ResolveStatusCode(Domain.Shared.Error error)
    {
        if (error.Code == RoleErrors.RoleNotFound.Code)
            return StatusCodes.Status400BadRequest;

        return base.ResolveStatusCode(error);
    }
}
