namespace Application.Feature.UserFeature.UserDto
{
    public class UserDisableInputDto
    {
        public Guid UserId { get; set; }
    }

    public class DisableUserRequest : UserDisableInputDto
    {
        public Guid UserToDisable
        {
            get => UserId;
            set => UserId = value;
        }
    }
}


