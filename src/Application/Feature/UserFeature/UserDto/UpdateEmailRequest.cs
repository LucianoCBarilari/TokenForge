namespace Application.Feature.UserFeature.UserDto
{
    public class UserEmailUpdateInputDto
    {
        public Guid UserId { get; set; }
        public string Email { get; set; } = string.Empty;
    }

    public class UpdateEmailRequest : UserEmailUpdateInputDto
    {
        public string NewEmail
        {
            get => Email;
            set => Email = value;
        }
    }
}


