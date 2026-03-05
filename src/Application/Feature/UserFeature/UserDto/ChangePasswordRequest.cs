namespace Application.Feature.UserFeature.UserDto
{
    public class UserPasswordChangeInputDto
    {
        public Guid UserId { get; set; }
        public string OldPassword { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
        public string ConfirmPassword { get; set; } = string.Empty;
    }

    public sealed class ChangePasswordRequest : UserPasswordChangeInputDto
    {
        public string ConfirmNewPassword
        {
            get => ConfirmPassword;
            set => ConfirmPassword = value;
        }
    }
}


