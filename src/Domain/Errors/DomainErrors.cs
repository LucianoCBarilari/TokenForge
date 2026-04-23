using Domain.Shared;

namespace Domain.Errors;

public record AuthErrors
{
    public static readonly Error InvalidLoginRequest = new("Auth.InvalidLoginRequest", "Invalid login request. Please provide valid credentials.");
    public static readonly Error InvalidCredentials = new("Auth.InvalidCredentials", "Invalid username or password.");
    public static readonly Error UserNotFound = new("Auth.UserNotFound", "User not found."); // Useful for more detailed responses or logging
    public static readonly Error UserLockedOut = new("Auth.UserLockedOut", "User account is locked out. Please try again later.");

    // Token Errors
    public static readonly Error MissingRefreshToken = new("Auth.MissingRefreshToken", "Refresh token is missing.");
    public static readonly Error InvalidRefreshToken = new("Auth.InvalidRefreshToken", "Invalid or expired refresh token.");
    public static readonly Error FailedToGenerateAccessToken = new("Auth.FailedToGenerateAccessToken", "Failed to generate a new access token.");
    // Logout Errors
    public static readonly Error LogoutFailed = new("Auth.LogoutFailed", "Logout failed. User may not be logged in or refresh token is invalid.");

    // General Authentication/Authorization Errors
    public static readonly Error Unauthorized = new("Auth.Unauthorized", "You are not authorized to perform this action.");
    public static readonly Error UserNotAuthenticated = new("Auth.UserNotAuthenticated", "User is not authenticated.");
    public static readonly Error InternalServerError = new("Auth.InternalServerError", "An internal server error occurred during authentication.");
    public static readonly Error UserIdRequired = new("Auth.UserIdRequired", "User ID is required for this operation.");
}
public record RoleErrors
{
    public static readonly Error RoleNotFound = new("Role.NotFound", "The specified role was not found.");
    public static readonly Error OperationFailed = new("Role.OperationFailed", "The role-related operation could not be completed.");
}
public record UserErrors
{
    public static readonly Error UserNotFound = new("User.NotFound", "The specified user was not found.");
    public static readonly Error UserAlreadyExists = new("User.AlreadyExists", "A user with the provided account or email already exists.");
    public static readonly Error EmailAlreadyInUse = new("User.EmailInUse", "The provided email address is already registered to another user.");
    public static readonly Error AccountAlreadyInUse = new("User.AccountInUse", "The provided user account name is already in use.");
    public static readonly Error InvalidPassword = new("User.InvalidPassword", "The provided password does not meet the complexity requirements or is incorrect.");
    public static readonly Error UserDisabled = new("User.Disabled", "The user account is currently disabled.");
    public static readonly Error OperationFailed = new("User.OperationFailed", "The user operation could not be completed.");
    public static readonly Error PasswordMismatch = new("User.PasswordMismatch", "The new password and confirmation password do not match.");
    public static readonly Error OldPasswordIncorrect = new("User.OldPasswordIncorrect", "The old password provided is incorrect.");
}
public record UserRoleErrors
{
    public static readonly Error UserNotFound = new("UserRole.UserNotFound", "The specified user for the role assignment was not found.");
    public static readonly Error RoleNotFound = new("UserRole.RoleNotFound", "The specified role for the role assignment was not found.");
    public static readonly Error UserAlreadyInRole = new("UserRole.UserAlreadyAssigned", "The user is already assigned to this active role.");
    public static readonly Error ActiveAssignmentNotFound = new("UserRole.ActiveAssignmentNotFound", "An active role assignment was not found for the specified user and role.");
    public static readonly Error UserRoleNotFound = new("UserRole.AssignmentNotFound", "The specified user-role assignment was not found.");
    public static readonly Error OperationFailed = new("UserRole.OperationFailed", "The user-role operation could not be completed.");
}
public record PermissionErrors
{
    public static readonly Error PermissionNotFound = new("Permission.NotFound", "The specified permission was not found.");
    public static readonly Error PermissionAlreadyExists = new("Permission.AlreadyExists", "A permission with the same code already exists.");
    public static readonly Error InvalidPermissionCode = new("Permission.InvalidCode", "Permission code is required.");
}
public record RolePermissionErrors
{
    public static readonly Error RoleNotFound = new("RolePermission.RoleNotFound", "The specified role was not found.");
    public static readonly Error PermissionNotFound = new("RolePermission.PermissionNotFound", "The specified permission was not found.");
    public static readonly Error RolePermissionAlreadyExists = new("RolePermission.AlreadyExists", "The role already has this active permission.");
    public static readonly Error RolePermissionNotFound = new("RolePermission.NotFound", "The specified role-permission assignment was not found.");
}

