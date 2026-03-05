namespace Application.Feature.RefreshTokenFeature
{
    public class RefreshAccessTokenRequest
    {
        public string RefreshToken { get; set; } = string.Empty;
        public Guid UserId { get; set; }
    }
}


