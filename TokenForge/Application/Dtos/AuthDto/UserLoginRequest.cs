using System.ComponentModel.DataAnnotations;

namespace TokenForge.Application.Dtos.AuthDto
{
    public class UserLoginRequest
    {
        public string UserAccount { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }
}


