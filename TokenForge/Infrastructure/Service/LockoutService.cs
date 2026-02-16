using TokenForge.Application.Dtos.UserDto;
using TokenForge.Domain.Entities;
using TokenForge.Infrastructure.DataAccess;

namespace TokenForge.Infrastructure.Service;

public class LockoutService(
    TokenForgeContext _dbContext,
    Helpers helper,
    ILogger<LockoutService> logger
    ) : ILockoutService
{

    public async Task<Result<LoginAttemptResponse>> LoginLockedChecker(string UAccount)
    {
        try
        {
            DateTime CurrentDate = helper.GetServerTimeUtc();
            var user = await _dbContext.Users
                                            .Where(x => x.UserAccount == UAccount)
                                            .FirstOrDefaultAsync();

            LoginAttempt? loginAttempt = await _dbContext.LoginAttempts
                                 .Where(x => x.UserAttempt == UAccount)
                                 .FirstOrDefaultAsync();

            if (loginAttempt == null)
            {
                return new LoginAttemptResponse { Succeeded = true };
            }

            if (user != null && loginAttempt.UserId == Guid.Empty)
            {
                loginAttempt.UserId = user.UsersId;
                _dbContext.LoginAttempts.Update(loginAttempt);
                await _dbContext.SaveChangesAsync();
            }

            if (loginAttempt.LockedUntil.HasValue && loginAttempt.LockedUntil > CurrentDate)
            {
                var errorMessage = $"User is locked out until {loginAttempt.LockedUntil:yyyy-MM-dd HH:mm:ss}";
                return new Error("Lockout.UserLocked", errorMessage);
            }

            return new LoginAttemptResponse
            {
                Succeeded = true,
                UserAttempt = loginAttempt
            };
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error checking login lockout for account {UAccount}", UAccount);
            return new Error("Lockout.CheckFailed", "An error occurred while checking login attempts.");
        }
    }

    public async Task<Result<LoginAttemptResponse>> ResetLoginAttempts(string userAccount)
    {
        try
        {
            DateTime currentDate = helper.GetServerTimeUtc();
            var user = await _dbContext.Users
                    .Where(x => x.UserAccount == userAccount)
                    .FirstOrDefaultAsync();

            var loginAttempt = await _dbContext.LoginAttempts
                                 .Where(x => x.UserAttempt == userAccount)
                                 .FirstOrDefaultAsync();

            if (loginAttempt == null)
            {
                return new Error("Lockout.NotFound", "No login attempt record found for this user");
            }

            loginAttempt.FailedAttempts = 0;
            loginAttempt.LockedUntil = null;
            loginAttempt.LastAttemptAt = currentDate;

            if (user != null && loginAttempt.UserId == Guid.Empty)
            {
                loginAttempt.UserId = user.UsersId;
            }
            _dbContext.LoginAttempts.Update(loginAttempt);
            await _dbContext.SaveChangesAsync();

            return new LoginAttemptResponse
            {
                Succeeded = true,
                UserAttempt = loginAttempt
            };
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error resetting login attempts for account {UserAccount}", userAccount);
            return new Error("Lockout.ResetFailed", "An error occurred while resetting login attempts.");
        }
    }

    public async Task<Result<LoginAttemptResponse>> RecordFailedLoginAttempt(string userAccount)
    {
        try
        {
            var user = await _dbContext.Users
                    .Where(x => x.UserAccount == userAccount)
                    .FirstOrDefaultAsync();

            if (user == null)
            {
                return new LoginAttemptResponse { Succeeded = true };
            }

            DateTime currentDate = helper.GetServerTimeUtc();

            var loginAttempt = await _dbContext.LoginAttempts
                                 .Where(x => x.UserAttempt == userAccount)
                                 .FirstOrDefaultAsync();

            if (loginAttempt == null)
            {
                loginAttempt = new LoginAttempt
                {
                    UserAttempt = userAccount,
                    UserId = user.UsersId,
                    FailedAttempts = 1,
                    LastAttemptAt = currentDate,
                    LockedUntil = null
                };
                await _dbContext.LoginAttempts.AddAsync(loginAttempt);
            }
            else
            {
                loginAttempt.FailedAttempts++;
                loginAttempt.LastAttemptAt = currentDate;

                if (loginAttempt.UserId == Guid.Empty)
                {
                    loginAttempt.UserId = user.UsersId;
                }

                if (loginAttempt.FailedAttempts >= 3)
                {
                    loginAttempt.LockedUntil = currentDate.AddMinutes(5);
                }
                _dbContext.LoginAttempts.Update(loginAttempt);
            }

            await _dbContext.SaveChangesAsync();

            string errorMessage = string.Empty;
            bool succeeded = true;

            if (loginAttempt.FailedAttempts >= 3)
            {
                succeeded = false;
                errorMessage = $"Account has been locked due to {loginAttempt.FailedAttempts} failed attempts. Locked until {loginAttempt.LockedUntil:yyyy-MM-dd HH:mm:ss}";
            }
            else
            {
                int remainingAttempts = 3 - loginAttempt.FailedAttempts;
                errorMessage = $"Invalid credentials. {remainingAttempts} attempt(s) remaining before account lockout";
            }

            return new LoginAttemptResponse
            {
                Succeeded = succeeded,
                UserAttempt = loginAttempt,
                ErrorMessage = errorMessage
            };
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error recording failed login attempt for account {UserAccount}", userAccount);
            return new Error("Lockout.RecordFailed", "An error occurred while recording login attempt.");
        }
    }
}