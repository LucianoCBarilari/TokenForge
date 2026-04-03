namespace Application.Feature.AuthFeature.AuthDto;

public sealed class LoginResponse
{
    public string AccessToken { get; set; } = string.Empty;
    public string TokenType { get; set; } = "Bearer";
    public Guid UserId { get; set; }
    public string UserAccount { get; set; } = string.Empty;

    public static LoginResponse FromAuth(AuthResponse auth) =>
        new()
        {
            AccessToken = auth.AccessToken,
            TokenType = auth.TokenType,
            UserId = auth.UserId,
            UserAccount = auth.UserAccount
        };
}
