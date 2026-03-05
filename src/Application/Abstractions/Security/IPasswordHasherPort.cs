namespace Application.Abstractions.Security;

public interface IPasswordHasherPort
{
    string Hash(string rawPassword);
    bool Verify(string hashedPassword, string rawPassword);
}
