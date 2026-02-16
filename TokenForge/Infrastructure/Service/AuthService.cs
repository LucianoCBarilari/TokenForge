using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using TokenForge.Application.Dtos.AuthDto;
using TokenForge.Application.Dtos.RoleDto;
using TokenForge.Application.Dtos.UserDto;
using TokenForge.Domain.Entities;
using TokenForge.Infrastructure.DataAccess;

namespace TokenForge.Infrastructure.Service;

public class AuthService(
    TokenForgeContext _dbContext,
    IConfiguration configuration,
    Helpers helper,
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
            var lockCheckResult = await LoginLockedChecker(UserLogin.UserAccount);
            if (lockCheckResult.IsFailure)
            {
                return AuthErrors.UserLockedOut;
            }
            
            var currentUser = await _dbContext.Users
                    .Where(x => x.UserAccount == UserLogin.UserAccount)
                    .FirstOrDefaultAsync();

            if (currentUser == null)
            {
                await RecordFailedLoginAttempt(UserLogin.UserAccount);
                return AuthErrors.InvalidCredentials;
            }

            var rolePerUserResult = await userRoleService.GetRolesByUserIdAsync(currentUser.UsersId);

            if (rolePerUserResult.IsFailure)
            {                    
                return rolePerUserResult.Error;
            }

            var rolePerUser = rolePerUserResult.Value;
            if (rolePerUser == null || !rolePerUser.Any())
            {
                return AuthErrors.Unauthorized; 
            }

            var rolesResult = await roleService.GetRolesForUserAsync(rolePerUser);
            if (rolesResult.IsFailure)
            {                    
                return rolesResult.Error;
            }
            var roles = rolesResult.Value;

            var passwordHasher = new PasswordHasher<User>();
            var pvr = passwordHasher.VerifyHashedPassword(currentUser, currentUser.PasswordHash, UserLogin.PasswordHash);

            if (pvr != PasswordVerificationResult.Success)
            {
                await RecordFailedLoginAttempt(UserLogin.UserAccount);
                return AuthErrors.InvalidCredentials;
            }

            var resetResult = await ResetLoginAttempts(UserLogin.UserAccount);
            if (resetResult.IsFailure)
            {
                logger.LogWarning($"Failed to reset login attempts for user {UserLogin.UserAccount}: {resetResult.Error.Message}");
            }

            Result<string> refreshTokenResult = await tokenService.CreateTokenAsync(currentUser.UsersId);
            if(refreshTokenResult.IsFailure)
            {
                return refreshTokenResult.Error;
            }

            var jwtToken = GenerateJwtToken(currentUser, roles);

            logger.LogInformation($"Successful login for user {UserLogin.UserAccount}");

            return AuthResponse.Success(jwtToken, refreshTokenResult.Value, 900);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, $"Error during login for user {UserLogin.UserAccount}");
            return AuthErrors.InternalServerError;
        }
    }
    public async Task<Result<string>> GenerateNewJwtToken(Guid UserId)
    {
        var userWithRolesResult = await userService.GetActiveUserWithRoles(UserId);

        if (userWithRolesResult.IsFailure)
        {
            
            return userWithRolesResult.Error;
        }
        
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
            logger.LogError(ex, $"Error during logout for user {UserId}");
            return Result.Failure(AuthErrors.InternalServerError);
        }
    }

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
