using Application.Abstractions.Security;
using Application.Constants;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Infrastructure.Security;

public class JwtProvider(IConfiguration configuration) : IJwtProvider
{
    public string CreateAccessToken(
        Guid userId,
        string email,
        List<string> roles,
        List<string> permissions)
    {
        string secret = configuration["JwtSettings:SecretKey"]
           ?? throw new InvalidOperationException("SecretKey not found.");

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));

        var accessTokenMinutesValue = configuration["JwtSettings:AccessTokenMinutes"]
            ?? throw new InvalidOperationException("JwtSettings:AccessTokenMinutes not found.");

        if (!int.TryParse(accessTokenMinutesValue, out var accessTokenMinutes))
            throw new InvalidOperationException("JwtSettings:AccessTokenMinutes must be an integer.");

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userId.ToString()),
            new(ClaimTypes.Email, email)
        };

        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }
        foreach (var perm in permissions) 
        {
            claims.Add(new Claim(CustomClaimTypes.Permission, perm));
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims, "jwt"),
            Expires = DateTime.UtcNow.AddMinutes(accessTokenMinutes),
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature),
            Issuer = configuration["JwtSettings:Issuer"],
            Audience = configuration["JwtSettings:Audience"]
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(descriptor);
        return tokenHandler.WriteToken(token);
    }
}
