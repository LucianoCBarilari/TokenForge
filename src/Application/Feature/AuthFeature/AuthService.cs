using Application.Abstractions.Common;
using Application.Abstractions.Security;
using Application.Feature.AuthFeature.AuthDto;
using Application.Feature.LockoutFeature;
using Application.Feature.RefreshTokenFeature;

namespace Application.Feature.AuthFeature;

public class AuthService(
    ILoginStore loginStore,
    ILockoutService lockoutService,
    ITransactionalUnitOfWork unitOfWork,
    IPasswordHasherPort passwordHasher,
    IJwtProvider jwtProvider,
    IHandleRefreshToken handleRefreshToken,
    IClock clock,
    ILogger<AuthService> logger) : IAuthService
{
    public async Task<Result<AuthResponse>> LoginAsync(User userLogin)
    {
        var currentUser = await loginStore.GetUserWithLastLoginAsync(userLogin.UserAccount);

        if (currentUser is null)
            return AuthErrors.InvalidCredentials;

        if (currentUser.LockedUntil.HasValue && currentUser.LockedUntil.Value > clock.UtcNow)
            return AuthErrors.UserLockedOut;

        if (currentUser.FailedAttempts >= 3 &&
            (!currentUser.LockedUntil.HasValue || currentUser.LockedUntil.Value > clock.UtcNow))
            return AuthErrors.UserLockedOut;

        if (!passwordHasher.Verify(currentUser.PasswordHash, userLogin.PasswordHash))
        {
            await lockoutService.RecordFailedLoginAttempt(userLogin.UserAccount);
            return AuthErrors.InvalidCredentials;
        }

        var rolesAndPermissions = await loginStore.GetUserRolesAndPermissionsAsync(currentUser.UsersId);
        if (rolesAndPermissions.Roles.Count == 0)
            return AuthErrors.Unauthorized;

        var permissionsCodes = rolesAndPermissions.Permissions.Values.ToList();
        var roleNames = rolesAndPermissions.Roles.Values.ToList();

        string refreshToken;

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
