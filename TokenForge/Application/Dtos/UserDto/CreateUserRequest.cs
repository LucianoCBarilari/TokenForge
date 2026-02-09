namespace TokenForge.Application.Dtos.UserDto
{
    public class CreateUserRequest
    {
        public string Email { get; set; } = string.Empty;
        public string UserAccount { get; set; } = string.Empty;
        public string Pass { get; set; } = string.Empty;
        public Guid RoleId { get; set; }
    }
}


