using Application.Abstractions.Common;
using Application.Abstractions.Security;
using Application.Common;
using Application.Feature.UserFeature.UserDto;

namespace Application.Feature.UserFeature;

public class UserService(
    IUserStore userStore,
    IRoleStore roleStore,
    IUserRoleStore userRoleStore,
    IPasswordHasherPort passwordHasher,
    IClock clock,
    Helpers helper,
    UserMapper mapper,
    ILogger<UserService> logger) : IUserService
{
    public async Task<Result> RegisterUser(UserCreateInputDto input)
    {
        input.Email = input.Email.ToLowerInvariant().Trim();
        input.UserAccount = input.UserAccount.ToLowerInvariant().Trim();
        input.Password = input.Password.Trim();

        if (!helper.EmailValidator(input.Email))
            return Result.Failure(new Error("User.InvalidEmailFormat", "Invalid email format."));

        if (!helper.AccountValidator(input.UserAccount))
            return Result.Failure(new Error("User.InvalidAccountFormat", "Invalid user account format. Must be 1-20 characters long and can only contain letters, numbers, and underscores."));

        if (await userStore.ExistsByEmailAsync(input.Email))
            return Result.Failure(UserErrors.EmailAlreadyInUse);

        if (await userStore.ExistsByAccountAsync(input.UserAccount))
            return Result.Failure(UserErrors.AccountAlreadyInUse);

        var role = await roleStore.GetByIdAsync(input.RoleId);
        if (role is null)
            return Result.Failure(RoleErrors.RoleNotFound);

        var user = mapper.ToEntity(input);
        user.PasswordHash = passwordHasher.Hash(input.Password);
        user.IsActive = true;
        user.CreatedAt = clock.UtcNow;

        await userStore.AddAsync(user);
        await userStore.SaveChangesAsync();

        var userRole = new UserRole
        {
            UserId = user.UsersId,
            RoleId = input.RoleId,
            AssignedAt = clock.UtcNow,
            IsActive = true
        };

        await userRoleStore.AddAsync(userRole);
        await userRoleStore.SaveChangesAsync();

        logger.LogInformation("User account created for {UserAccount}", user.UserAccount);
        return Result.Success();
    }

    public async Task<Result> UpdateEmail(UserEmailUpdateInputDto input)
    {
        if (input.UserId == Guid.Empty)
            return Result.Failure(new Error("User.UserIdRequired", "User ID is required."));

        input.Email = input.Email.ToLowerInvariant().Trim();

        if (string.IsNullOrWhiteSpace(input.Email) || !helper.EmailValidator(input.Email))
            return Result.Failure(new Error("User.InvalidEmailFormat", "Invalid email format."));

        var user = await userStore.GetByIdAsync(input.UserId);
        if (user is null)
            return Result.Failure(UserErrors.UserNotFound);

        if (!string.Equals(user.Email, input.Email, StringComparison.OrdinalIgnoreCase) &&
            await userStore.ExistsByEmailAsync(input.Email))
            return Result.Failure(UserErrors.EmailAlreadyInUse);

        user.Email = input.Email;
        user.UpdatedAt = clock.UtcNow;

        userStore.Update(user);
        await userStore.SaveChangesAsync();
        return Result.Success();
    }

    public async Task<Result> UpdateAccount(UserAccountUpdateInputDto input)
    {
        if (input.UserId == Guid.Empty)
            return Result.Failure(new Error("User.UserIdRequired", "User ID is required."));

        input.UserAccount = input.UserAccount.ToLowerInvariant().Trim();

        if (string.IsNullOrWhiteSpace(input.UserAccount) || !helper.AccountValidator(input.UserAccount))
            return Result.Failure(new Error("User.InvalidAccountFormat", "Invalid user account format."));

        var user = await userStore.GetByIdAsync(input.UserId);
        if (user is null)
            return Result.Failure(UserErrors.UserNotFound);

        if (!string.Equals(user.UserAccount, input.UserAccount, StringComparison.OrdinalIgnoreCase) &&
            await userStore.ExistsByAccountAsync(input.UserAccount))
            return Result.Failure(UserErrors.AccountAlreadyInUse);

        user.UserAccount = input.UserAccount;
        user.UpdatedAt = clock.UtcNow;

        userStore.Update(user);
        await userStore.SaveChangesAsync();
        return Result.Success();
    }

    public async Task<Result> UpdatePassword(UserPasswordChangeInputDto input)
    {
        if (input.UserId == Guid.Empty)
            return Result.Failure(new Error("User.UserIdRequired", "User ID is required."));

        if (string.IsNullOrWhiteSpace(input.OldPassword))
            return Result.Failure(new Error("User.OldPasswordRequired", "Old password is required."));

        input.NewPassword = input.NewPassword.Trim();
        input.ConfirmPassword = input.ConfirmPassword.Trim();

        if (!helper.PassValidator(input.NewPassword) || !helper.PassValidator(input.ConfirmPassword))
            return Result.Failure(UserErrors.InvalidPassword);

        if (!string.Equals(input.NewPassword, input.ConfirmPassword, StringComparison.Ordinal))
            return Result.Failure(UserErrors.PasswordMismatch);

        var user = await userStore.GetByIdAsync(input.UserId);
        if (user is null)
            return Result.Failure(UserErrors.UserNotFound);

        if (!passwordHasher.Verify(user.PasswordHash, input.OldPassword.Trim()))
            return Result.Failure(UserErrors.OldPasswordIncorrect);

        user.PasswordHash = passwordHasher.Hash(input.NewPassword);
        user.UpdatedAt = clock.UtcNow;

        userStore.Update(user);
        await userStore.SaveChangesAsync();
        return Result.Success();
    }

    public async Task<Result> DisableOneUser(UserDisableInputDto input)
    {
        var user = await userStore.GetByIdAsync(input.UserId);
        if (user is null)
            return Result.Failure(UserErrors.UserNotFound);

        user.IsActive = false;
        user.UpdatedAt = clock.UtcNow;
        userStore.Update(user);

        var activeRoles = await userRoleStore.GetActiveByUserIdAsync(user.UsersId);
        foreach (var assignment in activeRoles)
        {
            assignment.IsActive = false;
            assignment.DeactivatedAt = clock.UtcNow;
            userRoleStore.Update(assignment);
        }

        await userStore.SaveChangesAsync();
        await userRoleStore.SaveChangesAsync();

        return Result.Success();
    }

    public async Task<Result<UserResponse>> UserById(Guid userId)
    {
        var user = await userStore.GetByIdAsync(userId);
        if (user is null)
            return UserErrors.UserNotFound;

        return Result<UserResponse>.Success(mapper.ToResponse(user));
    }

    public async Task<Result<List<UserResponse>>> AllActiveUsers()
    {
        var users = await userStore.GetActiveAsync();
        return Result<List<UserResponse>>.Success(mapper.ToResponseList(users));
    }

    public async Task<Result<List<UserWithRolesResponse>>> GetAllActiveRoles()
    {
        var users = await userStore.GetActiveAsync();
        var result = new List<UserWithRolesResponse>(users.Count);

        foreach (var user in users)
        {
            var assignments = await userRoleStore.GetActiveByUserIdAsync(user.UsersId);
            var dto = mapper.ToWithRolesResponse(user);
            dto.Roles = assignments
                .Where(x => x.Role is not null && x.Role.IsActive)
                .Select(x => x.Role!)
                .ToList();
            result.Add(dto);
        }

        return Result<List<UserWithRolesResponse>>.Success(result);
    }

    public async Task<Result<UserWithRolesResponse>> GetActiveUserWithRoles(Guid userId)
    {
        var user = await userStore.GetByIdAsync(userId);
        if (user is null || !user.IsActive)
            return UserErrors.UserNotFound;

        var assignments = await userRoleStore.GetActiveByUserIdAsync(user.UsersId);
        var dto = mapper.ToWithRolesResponse(user);
        dto.Roles = assignments
            .Where(x => x.Role is not null && x.Role.IsActive)
            .Select(x => x.Role!)
            .ToList();

        return Result<UserWithRolesResponse>.Success(dto);
    }

    public async Task<Result<User>> GetUserByAccount(string account)
    {
        var normalizedAccount = account.ToLowerInvariant().Trim();
        var user = await userStore.GetByAccountAsync(normalizedAccount);
        if (user is null)
            return UserErrors.UserNotFound;

        return Result<User>.Success(user);
    }
}
