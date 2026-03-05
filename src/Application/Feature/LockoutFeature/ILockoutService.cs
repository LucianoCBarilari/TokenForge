using Application.Feature.UserFeature.UserDto;

namespace Application.Feature.LockoutFeature
{
    public interface ILockoutService
    {
        Task<Result<LoginAttemptResponse>> LoginLockedChecker(string userAccount);
        Task<Result<LoginAttemptResponse>> ResetLoginAttempts(string userAccount);
        Task<Result<LoginAttemptResponse>> RecordFailedLoginAttempt(string userAccount);
    }
}


