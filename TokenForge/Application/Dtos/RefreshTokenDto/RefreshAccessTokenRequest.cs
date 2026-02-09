namespace TokenForge.Application.Dtos.RefreshTokenDto
{
    public class RefreshAccessTokenRequest
    {
        public string RefreshToken { get; set; } = string.Empty;
        public Guid UserId { get; set; }
    }
}


