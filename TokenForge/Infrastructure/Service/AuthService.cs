using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using TokenForge.Application.Dtos.AuthDto;
using TokenForge.Application.Dtos.RoleDto;
using TokenForge.Application.Interfaces;
using TokenForge.Domain.Entities;
using TokenForge.Domain.Errors;
using TokenForge.Domain.Interfaces;
using TokenForge.Domain.Shared;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace TokenForge.Infrastructure.Service
{
    public class AuthService(
        IConfiguration configuration,
        ILockoutService lockoutService,
        ITokenService tokenService,
        IUserService userService,
        IUserRoleService userRoleService,
        IRoleService roleService,
        ILogger<AuthService> logger
        ) : IAuthService
    {
        public async Task<Result<AuthResponse>> LoginAsync(User UserLogin)
        {
            try
            {
                var lockCheckResult = await lockoutService.LoginLockedChecker(UserLogin.UserAccount);
                if (lockCheckResult.IsFailure)
                {
                    // Assuming the error from LockoutService is appropriate to return,
                    // or we can map it to a specific AuthError.
                    return AuthErrors.UserLockedOut;
                }
                
                var currentUserResult = await userService.GetUserByAccount(UserLogin.UserAccount);

                if (currentUserResult.IsFailure)
                {
                    await lockoutService.RecordFailedLoginAttempt(UserLogin.UserAccount);
                    return AuthErrors.InvalidCredentials;
                }
                var currentUser = currentUserResult.Value;

                var rolePerUserResult = await userRoleService.GetRolesByUserIdAsync(currentUser.UsersId);

                if (rolePerUserResult.IsFailure)
                {
                    // Propagate error from service, or return a more specific one
                    return rolePerUserResult.Error;
                }

                var rolePerUser = rolePerUserResult.Value;
                if (rolePerUser == null || !rolePerUser.Any())
                {
                    return AuthErrors.Unauthorized; // Or a more specific "UserHasNoRoles" error
                }

                var rolesResult = await roleService.GetRolesForUserAsync(rolePerUser);
                if (rolesResult.IsFailure)
                {
                    // Propagate error from service
                    return rolesResult.Error;
                }
                var roles = rolesResult.Value;

                var passwordHasher = new PasswordHasher<User>();
                var pvr = passwordHasher.VerifyHashedPassword(currentUser, currentUser.PasswordHash, UserLogin.PasswordHash);

                if (pvr != PasswordVerificationResult.Success)
                {
                    await lockoutService.RecordFailedLoginAttempt(UserLogin.UserAccount);
                    return AuthErrors.InvalidCredentials;
                }

                var resetResult = await lockoutService.ResetLoginAttempts(UserLogin.UserAccount);
                if (resetResult.IsFailure)
                {
                    logger.LogWarning("Failed to reset login attempts for user {UserLoginUserAccount}: {ErrorMessage}", UserLogin.UserAccount, resetResult.Error.Message);
                }

                Result<string> refreshTokenResult = await tokenService.CreateTokenAsync(currentUser.UsersId);
                if(refreshTokenResult.IsFailure)
                {
                    return refreshTokenResult.Error;
                }

                var jwtToken = GenerateJwtToken(currentUser, roles);

                logger.LogInformation("Successful login for user {UserLoginUserAccount}", UserLogin.UserAccount);

                return AuthResponse.Success(jwtToken, refreshTokenResult.Value, 900);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error during login for user {UserLoginUserAccount}", UserLogin.UserAccount);
                return AuthErrors.InternalServerError;
            }
        }
        public async Task<Result<string>> GenerateNewJwtToken(Guid UserId)
        {
            var userWithRolesResult = await userService.GetActiveUserWithRoles(UserId);

            if (userWithRolesResult.IsFailure)
            {
                // Propagate the error from the user service, e.g., UserNotFound
                return userWithRolesResult.Error;
            }

            // On success, get the actual object from the Value property
            var userWithRoles = userWithRolesResult.Value;

            var user = new User
            {
                UsersId = userWithRoles.UserId,
                Email = userWithRoles.Email,
                UserAccount = userWithRoles.UserAccount,
                IsActive = userWithRoles.IsActive
            };

            var rolesDto = userWithRoles.Roles.Select(r => new RoleResponse
            {
                RolesId = r.RolesId,
                RoleName = r.RoleName,
                RoleDescription = r.RoleDescription,
                IsActive = r.IsActive,
                CreatedAt = r.CreatedAt
            }).ToList();

            var newAccessToken = GenerateJwtToken(user, rolesDto);
            return newAccessToken;
        }
        private string GenerateJwtToken(User CUser, List<RoleResponse> CRoles) 
        {
            var TokenHandler = new JwtSecurityTokenHandler();

            var claims = new List<Claim>
            {
                new(ClaimTypes.NameIdentifier, CUser.UsersId.ToString()),
                new(ClaimTypes.Email, CUser.Email),
            };

            if (CRoles != null && CRoles.Any())
            {
                foreach (var role in CRoles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, role.RoleName));
                }
            }
            else
            {
                claims.Add(new Claim(ClaimTypes.Role, "Empty Role"));
            }

            var Key = Encoding.UTF8.GetBytes(configuration["JwtSettings:SecretKey"] ??
                      throw new InvalidOperationException("SecretKey not found."));

            var TokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims, "jwt"),
                Expires = DateTime.UtcNow.AddMinutes(30),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Key), SecurityAlgorithms.HmacSha256Signature),
                Issuer = configuration["JwtSettings:Issuer"],
                Audience = configuration["JwtSettings:Audience"]
            };
            var Token = TokenHandler.CreateToken(TokenDescriptor);

            return TokenHandler.WriteToken(Token);
        }
        public TokenValidationParameters GetValidationParameters()
        {
            return new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,

                ValidIssuer = configuration["JwtSettings:Issuer"],
                ValidAudience = configuration["JwtSettings:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JwtSettings:SecretKey"] ?? throw new InvalidOperationException("Secret Key not found")))
            };
        }
        public async Task<Result> LogoutAsync(Guid UserId, string RToken)
        {
            try
            {
                var result = await tokenService.RevokeCurrentSession(UserId, RToken);
                if (result.IsFailure)
                {
                    return Result.Failure(AuthErrors.LogoutFailed);
                }
                return Result.Success();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error during logout for user {UserId}", UserId);
                return Result.Failure(AuthErrors.InternalServerError);
            }
        }
    }
}



