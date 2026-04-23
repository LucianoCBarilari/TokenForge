namespace Web.Security;

public class AuthCookieWriter(IConfiguration configuration)
{
    private readonly int _accessTokenMinutesFallback =
      configuration.GetValue("AuthCookie:AccessTokenMinutesFallback", 30);

    private readonly int _refreshTokenDays =
      configuration.GetValue("AuthCookie:RefreshTokenDays", 30);

    //IDE0075 suggestion https://learn.microsoft.com/es-es/dotnet/fundamentals/code-analysis/style-rules/ide0075
    private readonly bool _secure = !bool.TryParse(configuration["AuthCookie:Secure"], out var secure) || secure;
    //IDE0075 suggestion https://learn.microsoft.com/es-es/dotnet/fundamentals/code-analysis/style-rules/ide0075
    private readonly bool _httpOnly = !bool.TryParse(configuration["AuthCookie:HttpOnly"], out var httpOnly) || httpOnly;

    private readonly SameSiteMode _sameSite = Enum.TryParse(configuration["AuthCookie:SameSite"], true, out SameSiteMode sameSite)
          ? sameSite
          : SameSiteMode.Strict;

    public CookieOptions BuildAccessTokenCookieOptions()
    {
        return new CookieOptions
        {
            HttpOnly = _httpOnly,
            Secure = _secure,
            SameSite = _sameSite,
            Expires = DateTime.UtcNow.AddMinutes(_accessTokenMinutesFallback)
        };
    }
    public CookieOptions BuildRefreshTokenCookieOptions()
    {
        return new CookieOptions
        {
            HttpOnly = _httpOnly,
            Secure = _secure,
            SameSite = _sameSite,
            Expires = DateTime.UtcNow.AddDays(_refreshTokenDays),
            Path = "/api/auth/tokens"
        };
    }

    public CookieOptions BuildRefreshTokenDeleteOptions()
    {
        return new CookieOptions
        {
            HttpOnly = _httpOnly,
            Secure = _secure,
            SameSite = _sameSite,
            Path = "/api/auth/tokens"
        };
    }
}