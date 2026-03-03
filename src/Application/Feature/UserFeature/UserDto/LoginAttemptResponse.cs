namespace Application.Feature.UserFeature.UserDto
{
    public class LoginAttemptResponse
    {
        public LoginAttempt UserAttempt { get; set; } = new();
        public bool Succeeded { get; set; } = false;
        public string ErrorMessage { get; set; } = string.Empty;
    }
}


