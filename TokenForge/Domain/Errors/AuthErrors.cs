using TokenForge.Domain.Shared;

namespace TokenForge.Domain.Errors
{
    public static class AuthErrors
    {
        public static readonly Error InvalidLoginRequest = new("Auth.InvalidLoginRequest", "Invalid login request. Please provide valid credentials.");
        public static readonly Error InvalidCredentials = new("Auth.InvalidCredentials", "Invalid username or password.");
        public static readonly Error UserNotFound = new("Auth.UserNotFound", "User not found."); // Useful for more detailed responses or logging
        public static readonly Error UserLockedOut = new("Auth.UserLockedOut", "User account is locked out. Please try again later.");
   
        // Token Errors
        public static readonly Error MissingRefreshToken = new("Auth.MissingRefreshToken", "Refresh token is missing.");
        public static readonly Error InvalidRefreshToken = new("Auth.InvalidRefreshToken", "Invalid or expired refresh token.");
        public static readonly Error FailedToGenerateAccessToken = new("Auth.FailedToGenerateAccessToken", "Failed to generate a new access token.");
        public static readonly Error TokenValidationFailed = new("Auth.TokenValidationFailed", "Access token validation failed.");
   
       // Logout Errors
        public static readonly Error LogoutFailed = new("Auth.LogoutFailed", "Logout failed. User may not be logged in or refresh token is invalid.");
   
        // General Authentication/Authorization Errors
        public static readonly Error Unauthorized = new("Auth.Unauthorized", "You are not authorized to perform this action.");
        public static readonly Error UserNotAuthenticated = new("Auth.UserNotAuthenticated", "User is not authenticated.");
        public static readonly Error InternalServerError = new("Auth.InternalServerError", "An internal server error occurred during authentication.");
        public static readonly Error UserIdRequired = new("Auth.UserIdRequired", "User ID is required for this operation.");
    }
}

