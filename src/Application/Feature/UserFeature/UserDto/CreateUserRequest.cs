namespace Application.Feature.UserFeature.UserDto
{
    public class UserCreateInputDto
    {
        public string Email { get; set; } = string.Empty;
        public string UserAccount { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public Guid RoleId { get; set; }
    }

    public sealed class CreateUserRequest : UserCreateInputDto
    {
        public string Pass
        {
            get => Password;
            set => Password = value;
        }
    }
}


