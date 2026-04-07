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

        var userStore = new UserStore(fixture.context);
        var userRoleStore = new UserRoleStore(fixture.context);
        var rolePermissionStore = new RolePermissionStore(fixture.context);

        tokenService = new TokenService(
            userStore, 
            userRoleStore, 
            rolePermissionStore,
            jwtProvider, 
            configMock.Object
            );
    }
    [Fact]
    public async Task GenerateNewAccessTokenAsync_ValidUser_ReturnsTokenWithRoles() 
    {
        var user = new User
        {
            UsersId = Guid.NewGuid(),
            Email = "test@planfi.com",
            IsActive = true,
           
        };
        fixture.context.Users.Add(user);

        var role = new Role
        {
            RolesId = Guid.NewGuid(),
            RoleName = "Admin",
            IsActive = true
        };
        fixture.context.Roles.Add(role);

        fixture.context.UserRoles.Add(new UserRole
        {
            UserId = user.UsersId,
            RoleId = role.RolesId,
            IsActive = true,
            AssignedAt = DateTime.UtcNow
        });
        await fixture.context.SaveChangesAsync();

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

        Assert.Contains("Admin", roleClaims);
    }
}
