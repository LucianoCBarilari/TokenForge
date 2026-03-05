using Application.Feature.UserFeature.UserDto;

namespace Application.Feature.UserFeature
{
    public interface IUserService
    {
        Task<Result> RegisterUser(UserCreateInputDto input);
        Task<Result> UpdateEmail(UserEmailUpdateInputDto input);
        Task<Result> UpdateAccount(UserAccountUpdateInputDto input);
        Task<Result> UpdatePassword(UserPasswordChangeInputDto input);
        Task<Result> DisableOneUser(UserDisableInputDto input);
        Task<Result<UserResponse>> UserById(Guid userId);
        Task<Result<List<UserResponse>>> AllActiveUsers();
        Task<Result<List<UserWithRolesResponse>>> GetAllActiveRoles();
        Task<Result<UserWithRolesResponse>> GetActiveUserWithRoles(Guid userId);
        Task<Result<User>> GetUserByAccount(string account);
    }
}


