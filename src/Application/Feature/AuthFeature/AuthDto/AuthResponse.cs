namespace Application.Feature.AuthFeature.AuthDto;

public class AuthResponse
{
    public string AccessToken { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public string TokenType { get; set; } = "Bearer";
    public Guid UserId { get; set; }
    public string UserAccount { get; set; } = string.Empty;
    public static AuthResponse Success(
        string accessToken,
        string refreshToken,
        Guid userId,
        string userAccount)
    {
        return new AuthResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            TokenType = "Bearer",
            UserId = userId,
            UserAccount = userAccount          
        };
    }
}
