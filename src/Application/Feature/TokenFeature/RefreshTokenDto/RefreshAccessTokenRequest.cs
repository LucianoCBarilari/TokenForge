namespace Application.Feature.TokenFeature.RefreshTokenDto
{
    public class RefreshAccessTokenRequest
    {
        public string RefreshToken { get; set; } = string.Empty;
        public Guid UserId { get; set; }
    }
}


