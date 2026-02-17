using Microsoft.AspNetCore.Identity;
using TokenForge.Application.Dtos.UserDto;
using TokenForge.Domain.Entities;
using TokenForge.Infrastructure.DataAccess;

namespace TokenForge.Application.Services;

public class UserService(
    TokenForgeContext _dbContext,
    Helpers helper,
    ILogger<UserService> logger
    ) : IUserService
{

    public async Task<Result> RegisterUser(CreateUserRequest NewUser)
    {
        try
        {
            NewUser.Email = NewUser.Email.ToLower().Trim();
            NewUser.UserAccount = NewUser.UserAccount.ToLower().Trim();
            NewUser.Pass = NewUser.Pass.Trim();


            if (!helper.EmailValidator(NewUser.Email))
                return Result.Failure(new Error("User.InvalidEmailFormat", "Invalid email format."));

            if (!helper.AccountValidator(NewUser.UserAccount))
                return Result.Failure(new Error("User.InvalidAccountFormat", "Invalid user account format. Must be 3-20 characters long and can only contain letters, numbers, and underscores."));

            /*review this snippet 
             * 
             * if (await _userRepository.GetRegisteredEmail(NewUser.Email))
                return Result.Failure(UserErrors.EmailAlreadyInUse);

            if (await _userRepository.GetRegisteredUserAccount(NewUser.UserAccount))
                return Result.Failure(UserErrors.AccountAlreadyInUse);*/

            var roleExist = await _dbContext.Roles.FindAsync(NewUser.RoleId);
            if (roleExist == null)
                return Result.Failure(RoleErrors.RoleNotFound);


            await using var transaction = await _dbContext.Database.BeginTransactionAsync();

            try
            {
                var passwordHasher = new PasswordHasher<User>();
                User CurrentUser = new()
                {
                    Email = NewUser.Email,
                    UserAccount = NewUser.UserAccount,
                    IsActive = true,
                    CreatedAt = helper.GetServerTimeUtc(),
                    PasswordHash = passwordHasher.HashPassword(new User(), NewUser.Pass.Trim())
                };

                await _dbContext.Users.AddAsync(CurrentUser);

                var userRole = new UserRole
                {
                    UserId = CurrentUser.UsersId,
                    RoleId = NewUser.RoleId,
                    AssignedAt = helper.GetServerTimeUtc(),
                    IsActive = true
                };

                await _dbContext.UserRoles.AddAsync(userRole);

                await _dbContext.SaveChangesAsync();
                await transaction.CommitAsync();

                return Result.Success();
            }
            catch (Exception transEx)
            {
                await transaction.RollbackAsync();
                logger.LogError(transEx, "Transaction failed during user registration for account {UserAccount}", NewUser.UserAccount);
                return Result.Failure(UserErrors.OperationFailed);
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error registering user {UserAccount}", NewUser.UserAccount);
            return Result.Failure(UserErrors.OperationFailed);
        }
    }

    public async Task<Result> UpdateEmail(UpdateEmailRequest NewMailObj)
    {
        try
        {
            var newEmail = NewMailObj.NewEmail.ToLower().Trim();

            if (NewMailObj.UserId == Guid.Empty)
                return Result.Failure(new Error("User.UserIdRequired", "User ID is required."));

            if (string.IsNullOrWhiteSpace(newEmail) || !helper.EmailValidator(newEmail))
                return Result.Failure(new Error("User.InvalidEmailFormat", "Invalid email format."));

            /*if (await _userRepository.GetRegisteredEmail(newEmail))
                return Result.Failure(UserErrors.EmailAlreadyInUse);*/

            var user = await _dbContext.Users.FindAsync(NewMailObj.UserId);
            if (user == null)
                return Result.Failure(UserErrors.UserNotFound);

            user.Email = newEmail;
            user.UpdatedAt = helper.GetServerTimeUtc();

            _dbContext.Users.Update(user);
            await _dbContext.SaveChangesAsync();
            return Result.Success();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error updating email for user {UserId}", NewMailObj.UserId);
            return Result.Failure(UserErrors.OperationFailed);
        }
    }

    public async Task<Result> UpdateAccount(UpdateUserAccountRequest UpdatedAccount)
    {
        try
        {
            var NewAccount = UpdatedAccount.NewAccount.ToLower().Trim();

            if (UpdatedAccount.UserId == Guid.Empty)
                return Result.Failure(new Error("User.UserIdRequired", "User ID is required."));

            if (string.IsNullOrWhiteSpace(NewAccount) || !helper.AccountValidator(NewAccount))
                return Result.Failure(new Error("User.InvalidAccountFormat", "Invalid user account format."));

            var user = await _dbContext.Users.FindAsync(UpdatedAccount.UserId);
            if (user == null)
                return Result.Failure(UserErrors.UserNotFound);

            /*if (await _userRepository.GetRegisteredUserAccount(NewAccount))
                return Result.Failure(UserErrors.AccountAlreadyInUse);*/

            user.UserAccount = NewAccount;
            user.UpdatedAt = helper.GetServerTimeUtc();

            _dbContext.Users.Update(user);
            await _dbContext.SaveChangesAsync();
            return Result.Success();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error updating account for user {UserId}", UpdatedAccount.UserId);
            return Result.Failure(UserErrors.OperationFailed);
        }
    }

    public async Task<Result> UpdatePassword(ChangePasswordRequest NewPasswordObj)
    {
        try
        {
            if (NewPasswordObj.UserId == Guid.Empty)
                return Result.Failure(new Error("User.UserIdRequired", "User ID is required."));

            if (string.IsNullOrWhiteSpace(NewPasswordObj.OldPassword))
                return Result.Failure(new Error("User.OldPasswordRequired", "Old password is required."));

            bool FlagTwo = helper.PassValidator(NewPasswordObj.NewPassword.Trim());
            bool FlagThree = helper.PassValidator(NewPasswordObj.ConfirmNewPassword.Trim());

            if (!FlagTwo || !FlagThree)
                return Result.Failure(UserErrors.InvalidPassword);

            if (NewPasswordObj.NewPassword.Trim() != NewPasswordObj.ConfirmNewPassword.Trim())
                return Result.Failure(UserErrors.PasswordMismatch);

            var user = await _dbContext.Users.FindAsync(NewPasswordObj.UserId);
            if (user == null)
                return Result.Failure(UserErrors.UserNotFound);

            PasswordHasher<User> PH = new();
            var VR = PH.VerifyHashedPassword(user, user.PasswordHash, NewPasswordObj.OldPassword.Trim());

            if (VR != PasswordVerificationResult.Success)
                return Result.Failure(UserErrors.OldPasswordIncorrect);

            user.PasswordHash = PH.HashPassword(user, NewPasswordObj.NewPassword.Trim());
            user.UpdatedAt = helper.GetServerTimeUtc();

            _dbContext.Users.Update(user);
            await _dbContext.SaveChangesAsync();
            return Result.Success();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error updating password for user {UserId}", NewPasswordObj.UserId);
            return Result.Failure(UserErrors.OperationFailed);
        }
    }

    public async Task<Result> DisableOneUser(DisableUserRequest UserToDisable)
    {
        try
        {
            var user = await _dbContext.Users.FindAsync(UserToDisable.UserToDisable);
            if (user == null)
                return Result.Failure(UserErrors.UserNotFound);

            user.IsActive = false;
            user.UpdatedAt = helper.GetServerTimeUtc();

            await using var transaction = await _dbContext.Database.BeginTransactionAsync();
            try
            {
                _dbContext.Users.Update(user);

                List<UserRole> userRoles = await _dbContext.UserRoles
                        .Where(ur => ur.UserId == user.UsersId && ur.IsActive)
                        .ToListAsync();

                foreach (var userRole in userRoles)
                {
                    userRole.IsActive = false;
                    _dbContext.UserRoles.Update(userRole);
                }

                await _dbContext.SaveChangesAsync();
                await transaction.CommitAsync();

                return Result.Success();
            }
            catch (Exception transEx)
            {
                await transaction.RollbackAsync();
                logger.LogError(transEx, "Transaction failed during user disable for user {UserId}", UserToDisable.UserToDisable);
                return Result.Failure(UserErrors.OperationFailed);
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error disabling user {UserId}", UserToDisable.UserToDisable);
            return Result.Failure(UserErrors.OperationFailed);
        }
    }

    public async Task<Result<UserResponse>> UserById(Guid UserId)
    {
        try
        {
            var userDb = await _dbContext.Users.FindAsync(UserId);

            if (userDb == null)
            {
                return UserErrors.UserNotFound;
            }
            return new UserResponse()
            {
                UserId = userDb.UsersId,
                Email = userDb.Email,
                UserAccount = userDb.UserAccount,
                IsActive = userDb.IsActive,
                CreatedAt = userDb.CreatedAt,
                UpdatedAt = userDb.UpdatedAt
            };
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error getting user by ID {UserId}", UserId);
            return UserErrors.OperationFailed;
        }
    }

    public async Task<Result<List<UserResponse>>> AllActiveUsers()
    {
        try
        {
            var users = await _dbContext.Users.Where(u => u.IsActive).ToListAsync();

            var mapped = users.Select(x => new UserResponse
            {
                UserId = x.UsersId,
                Email = x.Email,
                UserAccount = x.UserAccount,
                IsActive = x.IsActive,
                CreatedAt = x.CreatedAt,
                UpdatedAt = x.UpdatedAt
            }).ToList();

            return Result<List<UserResponse>>.Success(mapped);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error getting all active users.");
            return UserErrors.OperationFailed;
        }
    }

    public async Task<Result<List<UserWithRolesResponse>>> GetAllActiveRoles()
    {
        try
        {
            var users = await _dbContext.Users
                                            .AsNoTracking()
                                            .Where(u => u.IsActive)
                                            .Include(u => u.UserRoles)
                                            .ThenInclude(ur => ur.Role)
                                            .Select(u => new UserWithRolesResponse
                                            {
                                                UserId = u.UsersId,
                                                Email = u.Email,
                                                UserAccount = u.UserAccount,
                                                IsActive = u.IsActive,
                                                Roles = u.UserRoles
                                                    .Where(ur => ur.IsActive && ur.Role.IsActive)
                                                    .Select(ur => ur.Role)
                                                    .ToList()
                                            }).ToListAsync();

            return Result<List<UserWithRolesResponse>>.Success(users);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error getting all active users with roles.");
            return UserErrors.OperationFailed;
        }
    }

    public async Task<Result<UserWithRolesResponse>> GetActiveUserWithRoles(Guid userId)
    {
        try
        {
            var user = await _dbContext.Users
                                            .AsNoTracking()
                                            .Where(u => u.IsActive && u.UsersId == userId)
                                            .Include(u => u.UserRoles)
                                            .ThenInclude(ur => ur.Role)
                                            .Select(u => new UserWithRolesResponse
                                            {
                                                UserId = u.UsersId,
                                                Email = u.Email,
                                                UserAccount = u.UserAccount,
                                                IsActive = u.IsActive,
                                                Roles = u.UserRoles
                                                    .Where(ur => ur.IsActive && ur.Role.IsActive)
                                                    .Select(ur => ur.Role)
                                                    .ToList()
                                            }).FirstOrDefaultAsync();
            if (user == null)
            {
                return UserErrors.UserNotFound;
            }
            return user;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error getting active user with roles for ID {UserId}", userId);
            return UserErrors.OperationFailed;
        }
    }

    public async Task<Result<User>> GetUserByAccount(string account)
    {
        try
        {
            var user = await _dbContext.Users
                .Where(x => x.UserAccount == account)
                .FirstOrDefaultAsync();

            if (user == null)
            {
                return UserErrors.UserNotFound;
            }
            return user;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error getting user by account {Account}", account);
            return UserErrors.OperationFailed;
        }
    }
}
