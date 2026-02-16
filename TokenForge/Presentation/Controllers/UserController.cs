using TokenForge.Application.Dtos.UserDto;

namespace TokenForge.Presentation.Controllers;

    [Authorize]
    [ApiController]
    [Route("api/users")]
    public class UserController(
        IUserService userService,
        ILogger<UserController> logger
        ) : ControllerBase
{

        [HttpPost]
        public async Task<IActionResult> CreateNewUser([FromBody] CreateUserRequest request)
        {           
            var result = await userService.RegisterUser(request);

            if (result.IsFailure)
            {
                logger.LogWarning("Failed to create new user account for {UserAccount}: {Error}", request.UserAccount, result.Error.Message);
                return HandleFailure(result.Error);
            }
            return OkResponse(message: "User account created successfully.");
        }

        [HttpPut("{userId:guid}/email")]
        public async Task<IActionResult> UpdateEmail(Guid userId, [FromBody] UpdateEmailRequest updateEmailDto)
        {
            updateEmailDto.UserId = userId;
            
            var result = await userService.UpdateEmail(updateEmailDto);

            if (result.IsFailure)
            {
                logger.LogWarning("Failed to update email for user {UserId}: {Error}", updateEmailDto.UserId, result.Error.Message);
                return HandleFailure(result.Error);
            }
            return OkResponse(message: "Email updated successfully.");
        }

        [HttpPut("{userId:guid}/account")]
        public async Task<IActionResult> UpdateUserAccount(Guid userId, [FromBody] UpdateUserAccountRequest updateUserAccountDto)
        {
            updateUserAccountDto.UserId = userId;
            logger.LogInformation("Attempting to update account name for user {UserId} to {NewAccount}", updateUserAccountDto.UserId, updateUserAccountDto.NewAccount);
            var result = await userService.UpdateAccount(updateUserAccountDto);

            if (result.IsFailure)
            {
                logger.LogWarning("Failed to update account name for user {UserId}: {Error}", updateUserAccountDto.UserId, result.Error.Message);
                return HandleFailure(result.Error);
            }
            return OkResponse(message: "User account updated successfully.");
        }

        [HttpPut("{userId:guid}/password")]
        public async Task<IActionResult> UpdatePassword(Guid userId, [FromBody] ChangePasswordRequest changePasswordRequest)
        {
            changePasswordRequest.UserId = userId;            
            var result = await userService.UpdatePassword(changePasswordRequest);

            if (result.IsFailure)
            {
                logger.LogWarning("Failed to update password for user {UserId}: {Error}", changePasswordRequest.UserId, result.Error.Message);
                return HandleFailure(result.Error);
            }
            return OkResponse(message: "Password updated successfully.");
        }

        [HttpPut("{userId:guid}/disable")]
        public async Task<IActionResult> DisableUser(Guid userId, [FromBody] DisableUserRequest disableUserRequest)
        {
            disableUserRequest.UserToDisable = userId;
            var result = await userService.DisableOneUser(disableUserRequest);

            if (result.IsFailure)
            {
                logger.LogWarning("Failed to disable user {UserId}: {Error}", disableUserRequest.UserToDisable, result.Error.Message);
                return HandleFailure(result.Error);
            }
            return OkResponse(message: "User disabled successfully.");
        }

        [HttpGet("{userId:guid}")]
        public async Task<IActionResult> GetUserById(Guid userId)
        {
            var result = await userService.UserById(userId);

            if (result.IsFailure)
            {
                logger.LogWarning("Failed to retrieve user with ID {UserId}: {Error}", userId, result.Error.Message);
                return HandleFailure(result.Error);
            }
            return OkResponse(result.Value);
        }        

        [HttpGet("active")]
        public async Task<IActionResult> GetAllActiveUsers()
        {
            logger.LogInformation("Attempting to retrieve all active users.");
            var result = await userService.AllActiveUsers();

            if (result.IsFailure)
            {
                logger.LogWarning("Failed to retrieve all active users: {Error}", result.Error.Message);
                return HandleFailure(result.Error);
            }

            logger.LogInformation("Successfully retrieved all active users.");
            return OkResponse(result.Value);
        }

        [HttpGet("active-with-roles")]
        public async Task<IActionResult> GetActiveUsersWithRoles()
        {
            logger.LogInformation("Attempting to retrieve all active users with roles.");
            var result = await userService.GetAllActiveRoles();

            if (result.IsFailure)
            {
                logger.LogWarning("Failed to retrieve all active users with roles: {Error}", result.Error.Message);
                return HandleFailure(result.Error);
            }

            logger.LogInformation("Successfully retrieved all active users with roles.");
            return OkResponse(result.Value);
        }

        [HttpGet("{userId:guid}/with-roles")]
        public async Task<IActionResult> GetActiveUserWithRoles(Guid userId)
        {
            var result = await userService.GetActiveUserWithRoles(userId);

            if (result.IsFailure)
            {
                logger.LogWarning("Failed to retrieve active user with roles for ID {UserId}: {Error}", userId, result.Error.Message);
                return HandleFailure(result.Error);
            }
            return OkResponse(result.Value);
        }

        private IActionResult HandleFailure(Error error)
        {
            return error switch
            {
                { Code: var code } when code == UserErrors.UserNotFound.Code => FailResponse(error, StatusCodes.Status404NotFound),
                { Code: var code } when code == UserErrors.UserAlreadyExists.Code => FailResponse(error, StatusCodes.Status409Conflict),
                { Code: var code } when code == UserErrors.EmailAlreadyInUse.Code => FailResponse(error, StatusCodes.Status409Conflict),
                { Code: var code } when code == UserErrors.AccountAlreadyInUse.Code => FailResponse(error, StatusCodes.Status409Conflict),
                { Code: var code } when code == UserErrors.InvalidPassword.Code => FailResponse(error, StatusCodes.Status400BadRequest),
                { Code: var code } when code == UserErrors.PasswordMismatch.Code => FailResponse(error, StatusCodes.Status400BadRequest),
                { Code: var code } when code == UserErrors.OldPasswordIncorrect.Code => FailResponse(error, StatusCodes.Status401Unauthorized), 
                { Code: var code } when code == UserErrors.UserDisabled.Code => FailResponse(error, StatusCodes.Status401Unauthorized), 
                { Code: var code } when code == RoleErrors.RoleNotFound.Code => FailResponse(error, StatusCodes.Status400BadRequest), 
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