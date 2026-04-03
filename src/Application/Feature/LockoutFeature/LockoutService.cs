using Application.Abstractions.Common;
using Application.Feature.UserFeature.UserDto;

namespace Application.Feature.LockoutFeature;

public class LockoutService(
    IUserStore userStore,
    IAuthStore authStore,
    IClock clock) : ILockoutService
{
    public async Task<Result<LoginAttemptResponse>> LoginLockedChecker(string userAccount)
    {
        var currentUser = await userStore.GetByAccountAsync(userAccount);
        var loginAttempt = await authStore.GetLoginAttemptAsync(userAccount);

        if (loginAttempt is null)
            return Result<LoginAttemptResponse>.Success(new LoginAttemptResponse { Succeeded = true });

        if (currentUser is not null && loginAttempt.UserId == Guid.Empty)
        {
            loginAttempt.UserId = currentUser.UsersId;
            authStore.UpdateLoginAttempt(loginAttempt);
            await authStore.SaveChangesAsync();
        }

        if (loginAttempt.LockedUntil.HasValue && loginAttempt.LockedUntil > clock.UtcNow)
        {
            return Result<LoginAttemptResponse>.Failure(new Error("Lockout.UserLocked", $"User is locked out until {loginAttempt.LockedUntil:yyyy-MM-dd HH:mm:ss}"));
        }

        return Result<LoginAttemptResponse>.Success(new LoginAttemptResponse
        {
            Succeeded = true,
            UserAttempt = loginAttempt
        });
    }

    public async Task<Result<LoginAttemptResponse>> ResetLoginAttempts(string userAccount)
    {
        var currentUser = await userStore.GetByAccountAsync(userAccount);
        var loginAttempt = await authStore.GetLoginAttemptAsync(userAccount);
        
        if (loginAttempt is null)
        {
            return Result<LoginAttemptResponse>.Success(new LoginAttemptResponse
            {
                Succeeded = true
            });
        }
        loginAttempt.FailedAttempts = 0;
        loginAttempt.LockedUntil = null;
        loginAttempt.LastAttemptAt = clock.UtcNow;

        if (currentUser is not null && loginAttempt.UserId == Guid.Empty)
            loginAttempt.UserId = currentUser.UsersId;

        authStore.UpdateLoginAttempt(loginAttempt);
        await authStore.SaveChangesAsync();

        return Result<LoginAttemptResponse>.Success(new LoginAttemptResponse
        {
            Succeeded = true,
            UserAttempt = loginAttempt
        });
    }

    public async Task<Result<LoginAttemptResponse>> RecordFailedLoginAttempt(string userAccount)
    {
        var user = await userStore.GetByAccountAsync(userAccount);
        if (user is null)
        {
            return Result<LoginAttemptResponse>.Success(new LoginAttemptResponse { Succeeded = true });
        }

        var now = clock.UtcNow;
        var loginAttempt = await authStore.GetLoginAttemptAsync(userAccount);

        if (loginAttempt is null)
        {
            loginAttempt = new LoginAttempt
            {
                UserAttempt = userAccount,
                UserId = user.UsersId,
                FailedAttempts = 1,
                LastAttemptAt = now
            };
            await authStore.AddLoginAttemptAsync(loginAttempt);
        }
        else
        {
            loginAttempt.FailedAttempts++;
            loginAttempt.LastAttemptAt = now;

            if (loginAttempt.UserId == Guid.Empty)
                loginAttempt.UserId = user.UsersId;

            if (loginAttempt.FailedAttempts >= 3)
                loginAttempt.LockedUntil = now.AddMinutes(5);

            authStore.UpdateLoginAttempt(loginAttempt);
        }

        await authStore.SaveChangesAsync();

        var response = new LoginAttemptResponse
        {
            UserAttempt = loginAttempt
        };

        if (loginAttempt.FailedAttempts >= 3)
        {
            response.Succeeded = false;
            response.ErrorMessage = $"Account has been locked due to {loginAttempt.FailedAttempts} failed attempts. Locked until {loginAttempt.LockedUntil:yyyy-MM-dd HH:mm:ss}";
        }
        else
        {
            response.Succeeded = true;
            var remainingAttempts = 3 - loginAttempt.FailedAttempts;
            response.ErrorMessage = $"Invalid credentials. {remainingAttempts} attempt(s) remaining before account lockout";
        }

        return Result<LoginAttemptResponse>.Success(response);
    }
}
