namespace TokenForge.Application.Dtos.AuthDto
{
    public class AuthResponse
    {
        public string AccessToken { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
        public int ExpiresIn { get; set; }
        public string TokenType { get; set; } = "Bearer";

        public List<string> ErrorOrStatus { get; set; } = new();

        public bool IsSuccess => !ErrorOrStatus.Any() && !string.IsNullOrEmpty(AccessToken);
        public string Message { get; set; } = string.Empty;
        public bool IsLocked { get; set; } = false;
        public DateTime? LockedUntil { get; set; }

        public int StatusCode { get; set; } = 200;

        public static AuthResponse Success(string accessToken, string refreshToken, int expiresIn, string message = "Login successful")
        {
            return new AuthResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                ExpiresIn = expiresIn,
                Message = message,
                StatusCode = 200
            };
        }

        public static AuthResponse Error(string errorMessage, int statusCode = 401)
        {
            return new AuthResponse
            {
                ErrorOrStatus = new List<string> { errorMessage },
                Message = errorMessage,
                StatusCode = statusCode
            };
        }

        // ? Cambio aqu�: lockedUntil ahora es DateTime?
        public static AuthResponse Locked(string errorMessage, DateTime? lockedUntil = null)
        {
            return new AuthResponse
            {
                ErrorOrStatus = new List<string> { errorMessage },
                Message = errorMessage,
                IsLocked = true,
                LockedUntil = lockedUntil,
                StatusCode = 401
            };
        }

        public static AuthResponse BadRequest(string errorMessage)
        {
            return new AuthResponse
            {
                ErrorOrStatus = new List<string> { errorMessage },
                Message = errorMessage,
                StatusCode = 400
            };
        }

        public static AuthResponse InternalError(string errorMessage = "Internal server error")
        {
            return new AuthResponse
            {
                ErrorOrStatus = new List<string> { errorMessage },
                Message = errorMessage,
                StatusCode = 500
            };
        }
    }
}


