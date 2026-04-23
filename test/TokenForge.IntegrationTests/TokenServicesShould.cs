using Application.Abstractions.Security;
using Application.Feature.TokenFeature;
using Domain.Entities;
using Infrastructure.Ports.Persistence;
using Infrastructure.Security;
using Microsoft.Extensions.Configuration;
using Moq;
using System.Security.Claims;

namespace TokenForge.IntegrationTests;

public class TokenServicesShould : IClassFixture<SqlServerFixture>
{
    private readonly SqlServerFixture fixture;
    private readonly Mock<IConfiguration> configMock = new();
    private readonly IJwtProvider jwtProvider;
    private readonly TokenService tokenService;
    private readonly LoginStore loginStore;
    public TokenServicesShould(SqlServerFixture _fixture)
    {
        fixture = _fixture;

        configMock.Setup(c => c["RefreshTokenSecurity:HashKey"])
          .Returns("this-is-a-32-char-secret-key-for-tests-2026");

        configMock.Setup(c => c["JwtSettings:SecretKey"])
            .Returns("super-secret-key-with-enough-length-12345");

        configMock.Setup(c => c["JwtSettings:AccessTokenMinutes"])
            .Returns("60");

        configMock.Setup(c => c["JwtSettings:Issuer"])
            .Returns("TokenForge.Tests");

        configMock.Setup(c => c["JwtSettings:Audience"])
            .Returns("TokenForge.Clients");

        jwtProvider = new JwtProvider(configMock.Object);

        var userStore = new EfUserStore(fixture.Context);

        loginStore = new LoginStore(fixture.Context);

        tokenService = new TokenService(
            userStore,
            loginStore, 
            jwtProvider, 
            configMock.Object
            );
    }
    [Fact]
    public async Task GenerateNewAccessTokenAsync_ValidUser_ReturnsTokenWithRolesAndPermissions() 
    {     
        var user = new User
        {
            UsersId = Guid.NewGuid(),
            Email = "test@planfi.com",
            IsActive = true,
           
        };
        fixture.Context.Users.Add(user);

        var role = new Role
        {
            RolesId = Guid.NewGuid(),
            RoleName = "Admin",
            IsActive = true
        };
        fixture.Context.Roles.Add(role);

        fixture.Context.UserRoles.Add(new UserRole
        {
            UserId = user.UsersId,
            RoleId = role.RolesId,
            Role = role,
            IsActive = true,
            AssignedAt = DateTime.UtcNow
        });
        var permission = new Permission()
        {
            PermissionId = Guid.NewGuid(),
            PermissionCode = "manage.users",
            IsActive = true
        };
        fixture.Context.Permissions.Add(permission);

        fixture.Context.RolePermissions.Add(new RolePermission
        {
            RoleId = role.RolesId,
            PermissionId = permission.PermissionId,
            IsActive = true,
            AssignedAt = DateTime.UtcNow
        });
        await fixture.Context.SaveChangesAsync();   
        var result = await tokenService.GenerateNewAccessTokenAsync(user.UsersId);
        
        var tokenString = result.Value;          
        Assert.NotNull(tokenString);
        Assert.NotEmpty(tokenString);

        var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var jwtToken = tokenHandler.ReadJwtToken(tokenString);

        var roleClaims = jwtToken.Claims
            .Where(c => c.Type == "role" || c.Type == ClaimTypes.Role)
            .Select(c => c.Value)
            .ToList();
        var permissionClaims = jwtToken.Claims
            .Where(c => c.Type == "permission")
            .Select(c => c.Value)
            .ToList();

        Assert.Contains("manage.users", permissionClaims);
        Assert.Contains("Admin", roleClaims);
    }
    [Fact]
    public async Task GenerateNewAccessTokenAsync_InvalidUser_ReturnsNull()
    {
        var result = await tokenService.GenerateNewAccessTokenAsync(Guid.NewGuid());
        Assert.Null(result.Value);
    }
    [Fact]
    public async Task GenerateNewAccessTokenAsync_UserIsInactive_ReturnsNull()
    {
        var user = new User
        {
            UsersId = Guid.NewGuid(),
            Email = "test@planfi.com",
            IsActive = false,

        };
        await fixture.Context.SaveChangesAsync();

        var result = await tokenService.GenerateNewAccessTokenAsync(user.UsersId);
        Assert.Null(result.Value);
    }


    public async Task HashRefreshToken_()
    {
    }
}
