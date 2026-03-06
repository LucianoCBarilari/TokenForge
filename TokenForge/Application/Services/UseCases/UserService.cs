using Microsoft.AspNetCore.Identity;
using TokenForge.Application.Dtos.UserDto;
using TokenForge.Domain.Entities;
using TokenForge.Domain.Errors;
using TokenForge.Domain.Interfaces;
using TokenForge.Domain.Shared;
using TokenForge.Application.Interfaces;

namespace TokenForge.Application.Services.UseCases
{
    public class UserService(
        IHelpers helper,
        IUserRepository userRepository,
        IUserRoleRepository userRoleRepository,
        IRoleRepository roleRepository, // Added
        IUnitOfWork unitOfWork,
        ILogger<UserService> logger
        ) : IUserService
    {
        // Added

        public async Task<Result> RegisterUser(CreateUserRequest NewUserObj)
        {
            try
            {
                // Normalización de datos
                NewUserObj.Email = NewUserObj.Email.ToLower().Trim();
                NewUserObj.UserAccount = NewUserObj.UserAccount.ToLower().Trim();
                NewUserObj.Pass = NewUserObj.Pass.Trim();

                // Validaciones
                if (!helper.EmailValidator(NewUserObj.Email))
                    return Result.Failure(new Error("User.InvalidEmailFormat", "Invalid email format."));

                if (!helper.AccountValidator(NewUserObj.UserAccount))
                    return Result.Failure(new Error("User.InvalidAccountFormat", "Invalid user account format. Must be 3-20 characters long and can only contain letters, numbers, and underscores."));

                if (await userRepository.GetRegisteredEmail(NewUserObj.Email))
                    return Result.Failure(UserErrors.EmailAlreadyInUse);

                if (await userRepository.GetRegisteredUserAccount(NewUserObj.UserAccount))
                    return Result.Failure(UserErrors.AccountAlreadyInUse);

                var roleExist = await roleRepository.GetByIdAsync(NewUserObj.RoleId);
                if (roleExist == null)
                    return Result.Failure(RoleErrors.RoleNotFound); // Assuming RoleErrors is still used for role validation

                // TRANSACTION
                await using var transaction = await unitOfWork.BeginTransactionAsync();

                try
                {
                    var passwordHasher = new PasswordHasher<User>();
                    User CurrentUser = new()
                    {
                        Email = NewUserObj.Email,
                        UserAccount = NewUserObj.UserAccount,
                        IsActive = true,
                        CreatedAt = helper.GetBuenosAiresTime(),
                        PasswordHash = passwordHasher.HashPassword(new User(), NewUserObj.Pass.Trim()) // Pass empty User object to hasher
                    };

                    // Insertar vía repositorio
                    await userRepository.AddAsync(CurrentUser); // Use specific repository
                    // No SaveChangesAsync here, will save once at the end of transaction

                    // Crear user role
                    var userRole = new UserRole
                    {
                        UserId = CurrentUser.UsersId,
                        RoleId = NewUserObj.RoleId,
                        AssignedAt = helper.GetBuenosAiresTime(),
                        IsActive = true
                    };

                    await userRoleRepository.AddAsync(userRole); // Use specific repository
                    // No SaveChangesAsync here, will save once at the end of transaction

                    await unitOfWork.SaveChangesAsync();
                    await transaction.CommitAsync();
                    return Result.Success();
                }
                catch (Exception transEx)
                {
                    await transaction.RollbackAsync();
                    logger.LogError(transEx, "Transaction failed during user registration for account {UserAccount}", NewUserObj.UserAccount);
                    return Result.Failure(UserErrors.OperationFailed);
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error registering user {UserAccount}", NewUserObj.UserAccount);
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

                if (await userRepository.GetRegisteredEmail(newEmail))
                    return Result.Failure(UserErrors.EmailAlreadyInUse);

                var user = await userRepository.GetByIdAsync(NewMailObj.UserId);
                if (user == null)
                    return Result.Failure(UserErrors.UserNotFound);

                user.Email = newEmail;
                user.UpdatedAt = helper.GetBuenosAiresTime();

                await userRepository.UpdateAsync(user);
                await userRepository.SaveChangesAsync(); // Use specific repository's SaveChangesAsync
                return Result.Success();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error updating email for user {UserId}", NewMailObj.UserId);
                return Result.Failure(UserErrors.OperationFailed);
            }
        }

        public async Task<Result> UpdateAccount(UpdateUserAccountRequest NewAccountObj)
        {
            try
            {
                var NewAccount = NewAccountObj.NewAccount.ToLower().Trim();

                if (NewAccountObj.UserId == Guid.Empty)
                    return Result.Failure(new Error("User.UserIdRequired", "User ID is required."));

                if (string.IsNullOrWhiteSpace(NewAccount) || !helper.AccountValidator(NewAccount))
                    return Result.Failure(new Error("User.InvalidAccountFormat", "Invalid user account format."));

                var user = await userRepository.GetByIdAsync(NewAccountObj.UserId);
                if (user == null)
                    return Result.Failure(UserErrors.UserNotFound);

                if (await userRepository.GetRegisteredUserAccount(NewAccount))
                    return Result.Failure(UserErrors.AccountAlreadyInUse);

                user.UserAccount = NewAccount;
                user.UpdatedAt = helper.GetBuenosAiresTime();

                await userRepository.UpdateAsync(user);
                await userRepository.SaveChangesAsync(); // Use specific repository's SaveChangesAsync
                return Result.Success();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error updating account for user {UserId}", NewAccountObj.UserId);
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

                var user = await userRepository.GetByIdAsync(NewPasswordObj.UserId);
                if (user == null)
                    return Result.Failure(UserErrors.UserNotFound);

                PasswordHasher<User> PH = new();
                var VR = PH.VerifyHashedPassword(user, user.PasswordHash, NewPasswordObj.OldPassword.Trim());

                if (VR != PasswordVerificationResult.Success)
                    return Result.Failure(UserErrors.OldPasswordIncorrect);

                user.PasswordHash = PH.HashPassword(user, NewPasswordObj.NewPassword.Trim());
                user.UpdatedAt = helper.GetBuenosAiresTime();

                await userRepository.UpdateAsync(user);
                await userRepository.SaveChangesAsync(); // Use specific repository's SaveChangesAsync
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
                var user = await userRepository.GetByIdAsync(UserToDisable.UserToDisable);
                if (user == null)
                    return Result.Failure(UserErrors.UserNotFound);

                user.IsActive = false;
                user.UpdatedAt = helper.GetBuenosAiresTime();

                await using var transaction = await unitOfWork.BeginTransactionAsync();
                try
                {
                    await userRepository.UpdateAsync(user);
                    List<UserRole> userRoles = await userRoleRepository.GetUserRolesActivesByIdAsync(user);

                    foreach (var userRole in userRoles)
                    {
                        userRole.IsActive = false;
                        await userRoleRepository.UpdateAsync(userRole); // Use specific repository's UpdateAsync
                    }
                    // _context.UserRoles.UpdateRange(userRoles); // No longer needed with specific repository updates

                    await unitOfWork.SaveChangesAsync();
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
                var userDb = await userRepository.GetByIdAsync(UserId);

                if (userDb == null) // Check if user is null
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
                var users = await userRepository.GetAllActiveUsers();
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
                var users = await userRepository.GetActiveUsersWithRolesAsync() ?? new List<UserWithRolesResponse>();
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
                var user = await userRepository.GetActiveUserWithRolesAsync(userId);
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
                var user = await userRepository.GetByAccountAsync(account);
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
}



