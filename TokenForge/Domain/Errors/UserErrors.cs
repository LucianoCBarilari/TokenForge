namespace TokenForge.Domain.Errors;

using TokenForge.Domain.Shared;

public static class UserErrors
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

