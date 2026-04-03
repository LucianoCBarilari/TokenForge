using Application.Abstractions.Security;
using Domain.Entities;
using Microsoft.AspNetCore.Identity;

namespace Infrastructure.Security;

public class AspNetPasswordHasherPort : IPasswordHasherPort
{
    private readonly PasswordHasher<User> _passwordHasher = new();

    public string Hash(string rawPassword)
    {
        return _passwordHasher.HashPassword(new User(), rawPassword);
    }

    public bool Verify(string hashedPassword, string rawPassword)
    {
        var verificationResult = _passwordHasher.VerifyHashedPassword(new User(), hashedPassword, rawPassword);
        return verificationResult is PasswordVerificationResult.Success or PasswordVerificationResult.SuccessRehashNeeded;
    }
}
