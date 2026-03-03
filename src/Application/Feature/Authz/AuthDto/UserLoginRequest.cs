namespace Application.Feature.Authz.AuthDto
{
    public class UserLoginRequest
    {
        public string UserAccount { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }
}


