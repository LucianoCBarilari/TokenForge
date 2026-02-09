using TokenForge.Application.Dtos.UserDto;
using TokenForge.Domain.Shared;

namespace TokenForge.Application.Interfaces
{
    public interface ILockoutService
    {
        Task<Result<LoginAttemptResponse>> LoginLockedChecker(string UAccount);
        Task<Result<LoginAttemptResponse>> ResetLoginAttempts(string userAccount);
        Task<Result<LoginAttemptResponse>> RecordFailedLoginAttempt(string userAccount);
    }
}


