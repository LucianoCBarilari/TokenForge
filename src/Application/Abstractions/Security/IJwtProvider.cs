namespace Application.Abstractions.Security;

public interface IJwtProvider
{
    string CreateAccessToken(Guid userId,string email,List<string> roles,List<string> permissions);
}
