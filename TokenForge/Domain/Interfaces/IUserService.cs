using TokenForge.Application.Common;
using TokenForge.Application.Dtos.UserDto;
using TokenForge.Domain.Entities;
using TokenForge.Domain.Shared; // Add this using statement

namespace TokenForge.Domain.Interfaces
{
    public interface IUserService
    {
        Task<Result> RegisterUser(CreateUserRequest NewUserObj);
        Task<Result> UpdateEmail(UpdateEmailRequest NewMailObj);
        Task<Result> UpdateAccount(UpdateUserAccountRequest NewAccountObj);
        Task<Result> UpdatePassword(ChangePasswordRequest NewPasswordObj);
        Task<Result> DisableOneUser(DisableUserRequest UserToDisable);
        Task<Result<UserResponse>> UserById(Guid UserId);
        Task<Result<List<UserResponse>>> AllActiveUsers();
        Task<Result<List<UserWithRolesResponse>>> GetAllActiveRoles();
        Task<Result<UserWithRolesResponse>> GetActiveUserWithRoles(Guid userId);
        Task<Result<User>> GetUserByAccount(string account);
    }
}


