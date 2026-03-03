namespace Application.Abstractions.Security;

public interface IJwtProvider
{
    string CreateAccessToken(
        Guid userId,
        string email,
        IReadOnlyCollection<string> roles,
        TimeSpan lifetime);
}
