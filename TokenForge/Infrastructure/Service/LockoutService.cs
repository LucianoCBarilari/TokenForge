using Microsoft.Extensions.Logging;
using TokenForge.Application.Dtos.UserDto;
using TokenForge.Application.Interfaces;
using TokenForge.Domain.Entities;
using TokenForge.Domain.Interfaces;
using TokenForge.Domain.Shared;

namespace TokenForge.Infrastructure.Service
{
    public class LockoutService(
        IHelpers helper,
        IUserRepository userRepository,
        ILoginAttemptRepository loginAttemptRepository,
        ILogger<LockoutService> logger
        ) : ILockoutService
    {
        private readonly IHelpers _helper = helper;
        private readonly IUserRepository _userRepository = userRepository;
        private readonly ILoginAttemptRepository _loginAttemptRepository = loginAttemptRepository;
        private readonly ILogger<LockoutService> _logger = logger;

        public async Task<Result<LoginAttemptResponse>> LoginLockedChecker(string UAccount)
        {
            try
            {
                DateTime CurrentDate = _helper.GetServerTimeUtc();
                var user = await _userRepository.GetByAccountAsync(UAccount);
                LoginAttempt? loginAttempt = await _loginAttemptRepository.GetInfoByUserAccount(UAccount);
                
                if (loginAttempt == null)
                {
                    return new LoginAttemptResponse { Succeeded = true }; // No restrictions if no attempt record
                }

                if (user != null && loginAttempt.UserId == Guid.Empty)
                {
                    loginAttempt.UserId = user.UsersId;
                    await _loginAttemptRepository.UpdateAsync(loginAttempt);
                    await _loginAttemptRepository.SaveChangesAsync();
                }

                if (loginAttempt.LockedUntil.HasValue && loginAttempt.LockedUntil > CurrentDate)
                {
                    var errorMessage = $"User is locked out until {loginAttempt.LockedUntil:yyyy-MM-dd HH:mm:ss}";
                    // This is a failure from the perspective of logging in.
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
                _logger.LogError(ex, "Error checking login lockout for account {UAccount}", UAccount);
                return new Error("Lockout.CheckFailed", "An error occurred while checking login attempts.");
            }
        }

        public async Task<Result<LoginAttemptResponse>> ResetLoginAttempts(string userAccount)
        {
            try
            {
                DateTime currentDate = _helper.GetServerTimeUtc();
                var user = await _userRepository.GetByAccountAsync(userAccount);
                var loginAttempt = await _loginAttemptRepository.GetInfoByUserAccount(userAccount);

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
                await _loginAttemptRepository.UpdateAsync(loginAttempt);
                await _loginAttemptRepository.SaveChangesAsync();
                
                return new LoginAttemptResponse
                {
                    Succeeded = true,
                    UserAttempt = loginAttempt
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error resetting login attempts for account {UserAccount}", userAccount);
                return new Error("Lockout.ResetFailed", "An error occurred while resetting login attempts.");
            }
        }

        public async Task<Result<LoginAttemptResponse>> RecordFailedLoginAttempt(string userAccount)
        {
            try
            {
                var user = await _userRepository.GetByAccountAsync(userAccount);

                // If the user does not exist, we cannot record a login attempt against them
                // due to the FOREIGN KEY constraint. The login will fail regardless.
                if (user == null)
                {
                    // Silently succeed, as there's no user to lock out.
                    // The authentication service will handle the "user not found" error.
                    return new LoginAttemptResponse { Succeeded = true };
                }

                DateTime currentDate = _helper.GetServerTimeUtc();
                var loginAttempt = await _loginAttemptRepository.GetInfoByUserAccount(userAccount);

                if (loginAttempt == null)
                {
                    loginAttempt = new LoginAttempt
                    {
                        UserAttempt = userAccount,
                        UserId = user.UsersId, // We know the user exists here.
                        FailedAttempts = 1,
                        LastAttemptAt = currentDate,
                        LockedUntil = null
                    };
                    await _loginAttemptRepository.AddAsync(loginAttempt);
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
                    await _loginAttemptRepository.UpdateAsync(loginAttempt);
                }

                await _loginAttemptRepository.SaveChangesAsync();

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
                _logger.LogError(ex, "Error recording failed login attempt for account {UserAccount}", userAccount);
                return new Error("Lockout.RecordFailed", "An error occurred while recording login attempt.");
            }
        }
    }
}



