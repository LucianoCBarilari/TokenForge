namespace Application.Feature.UserFeature.UserDto
{
    public class UserAccountUpdateInputDto
    {
        public Guid UserId { get; set; }
        public string UserAccount { get; set; } = string.Empty;
    }

    public class UpdateUserAccountRequest : UserAccountUpdateInputDto
    {
        public string NewAccount
        {
            get => UserAccount;
            set => UserAccount = value;
        }
    }
}


