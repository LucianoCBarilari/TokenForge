namespace TokenForge.Domain.Errors;

using TokenForge.Domain.Shared;

public static class RoleErrors
{
    public static readonly Error RoleNotFound = new("Role.NotFound", "The specified role was not found.");
    public static readonly Error OperationFailed = new("Role.OperationFailed", "The role-related operation could not be completed.");
}

