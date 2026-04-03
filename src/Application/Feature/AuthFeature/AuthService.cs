using Application.Abstractions.Security;
using Application.Feature.AuthFeature.AuthDto;
using Application.Feature.LockoutFeature;
using Application.Feature.RefreshTokenFeature;

namespace Application.Feature.AuthFeature;

public class AuthService(
    IUserStore userStore,
    IUserRoleStore userRoleStore,
    IRolePermissionStore rolePermissionStore,
    ILockoutService lockoutService,
    ITransactionalUnitOfWork unitOfWork,
    IPasswordHasherPort passwordHasher,
    IJwtProvider jwtProvider,
    IHandleRefreshToken handleRefreshToken,
    ILogger<AuthService> logger) : IAuthService
{    
    

    public async Task<Result<AuthResponse>> LoginAsync(User userLogin)
    {
        var currentUser = await userStore.GetByAccountAsync(userLogin.UserAccount);
        if (currentUser is null)
        {
            await lockoutService.RecordFailedLoginAttempt(userLogin.UserAccount);
            return AuthErrors.InvalidCredentials;
        }
        if (!passwordHasher.Verify(currentUser.PasswordHash, userLogin.PasswordHash))
        {
            await lockoutService.RecordFailedLoginAttempt(userLogin.UserAccount);
            return AuthErrors.InvalidCredentials;
        }

        var lockCheck = await lockoutService.LoginLockedChecker(userLogin.UserAccount);
        if (lockCheck.IsFailure)
            return AuthErrors.UserLockedOut;
        
        /*Role And Permission Claims*/
        List<Guid> roleIds = await userRoleStore.GetActiveRoleIdsByUserIdAsync(currentUser.UsersId);
        if (roleIds.Count == 0)
            return AuthErrors.Unauthorized;

        var permissionsCodes = await rolePermissionStore.GetActivePermissionCodesByRoleIdsAsync(roleIds);

        var roleNames = await userRoleStore.GetActiveRoleNamesByUserIdAsync(currentUser.UsersId);

        string refreshToken = string.Empty;
        // Wrap in a transaction for atomicity.
        // ResetLoginAttemptsAsync updates the failed attempts count,
        // while CreateRefreshTokenAsync inserts a new refresh token record.
        // Both must succeed or roll back together.        
        try
        {
            await unitOfWork.BeginTransactionAsync();
            var resetResult = await lockoutService.ResetLoginAttempts(userLogin.UserAccount);

            if (resetResult.IsFailure)
            {
                await unitOfWork.RollbackAsync();
                return resetResult.Error;
            }


            var refreshTokenResult = await handleRefreshToken.CreateRefreshTokenAsync(currentUser.UsersId);
            if (refreshTokenResult.IsFailure)
            {
                await unitOfWork.RollbackAsync();
                return refreshTokenResult.Error;
            }
            refreshToken = refreshTokenResult.Value;
            await unitOfWork.CommitAsync();
        }
        catch (Exception ex)
        {
            await unitOfWork.RollbackAsync();
            logger.LogError(ex, "Login transaction failed for {UserAccount}", userLogin.UserAccount);
            return AuthErrors.InternalServerError;
        }
        /*End of Transaction*/

        var accessToken = jwtProvider.CreateAccessToken(
            currentUser.UsersId,
            currentUser.Email,
            roleNames,
            permissionsCodes);

        return Result<AuthResponse>.Success(AuthResponse.Success(
            accessToken,
            refreshToken,
            currentUser.UsersId,
            currentUser.UserAccount));
    }
    public async Task<Result> LogoutAsync(Guid userId, string refreshToken)
    {
        var result = await handleRefreshToken.RevokeCurrentSession(userId, refreshToken);
        if (result.IsFailure)
            return Result.Failure(AuthErrors.LogoutFailed);

        return Result.Success();
    }
}
