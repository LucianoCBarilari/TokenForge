using Application.Abstractions.Security;
using Application.Feature.Authz.AuthDto;
using Application.Feature.LockoutFeature;
using Application.Feature.TokenFeature;

namespace Application.Feature.Authz;

public class AuthService(
    IUserStore userStore,
    IUserRoleStore userRoleStore,
    ILockoutService lockoutService,
    IPasswordHasherPort passwordHasher,
    IJwtProvider jwtProvider,
    ITokenService tokenService,
    ILogger<AuthService> logger) : IAuthService
{    
    

    public async Task<Result<AuthResponse>> LoginAsync(User userLogin)
    {
        var lockCheck = await lockoutService.LoginLockedChecker(userLogin.UserAccount);
        if (lockCheck.IsFailure)
            return AuthErrors.UserLockedOut;

        var currentUser = await userStore.GetByAccountAsync(userLogin.UserAccount);
        if (currentUser is null)
        {
            await lockoutService.RecordFailedLoginAttempt(userLogin.UserAccount);
            return AuthErrors.InvalidCredentials;
        }

        var roleNames = await userRoleStore.GetActiveRoleNamesByUserIdAsync(currentUser.UsersId);
        if (roleNames.Count == 0)
            return AuthErrors.Unauthorized;

        if (!passwordHasher.Verify(currentUser.PasswordHash, userLogin.PasswordHash))
        {
            await lockoutService.RecordFailedLoginAttempt(userLogin.UserAccount);
            return AuthErrors.InvalidCredentials;
        }

        var resetResult = await lockoutService.ResetLoginAttempts(userLogin.UserAccount);
        if (resetResult.IsFailure)
        {
            logger.LogWarning("Failed to reset login attempts for {UserAccount}: {Error}", userLogin.UserAccount, resetResult.Error.Message);
        }

        var refreshTokenResult = await tokenService.CreateTokenAsync(currentUser.UsersId);
        if (refreshTokenResult.IsFailure)
            return refreshTokenResult.Error;

        var accessToken = jwtProvider.CreateAccessToken(
            currentUser.UsersId,
            currentUser.Email,
            roleNames);

        return Result<AuthResponse>.Success(AuthResponse.Success(
            accessToken,
            refreshTokenResult.Value,
            currentUser.UsersId,
            currentUser.UserAccount,
            roleNames));
    }
    public async Task<Result> LogoutAsync(Guid userId, string refreshToken)
    {
        var result = await tokenService.RevokeCurrentSession(userId, refreshToken);
        if (result.IsFailure)
            return Result.Failure(AuthErrors.LogoutFailed);

        return Result.Success();
    }
}
