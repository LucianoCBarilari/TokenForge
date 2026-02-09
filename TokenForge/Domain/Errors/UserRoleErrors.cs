namespace TokenForge.Domain.Errors;

using TokenForge.Domain.Shared;

public static class UserRoleErrors
{
    public static readonly Error UserNotFound = new("UserRole.UserNotFound", "The specified user for the role assignment was not found.");
    public static readonly Error RoleNotFound = new("UserRole.RoleNotFound", "The specified role for the role assignment was not found.");
    public static readonly Error UserAlreadyInRole = new("UserRole.UserAlreadyAssigned", "The user is already assigned to this active role.");
    public static readonly Error ActiveAssignmentNotFound = new("UserRole.ActiveAssignmentNotFound", "An active role assignment was not found for the specified user and role.");
    public static readonly Error UserRoleNotFound = new("UserRole.AssignmentNotFound", "The specified user-role assignment was not found.");
    public static readonly Error OperationFailed = new("UserRole.OperationFailed", "The user-role operation could not be completed.");
}

