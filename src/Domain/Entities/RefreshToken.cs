namespace Domain.Entities;

public class RefreshToken
{
    public Guid RefreshTokensId { get; set; }
    public string Token { get; set; } = string.Empty;
    public Guid UserId { get; set; }
    public User? User { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? RevokedAt { get; set; }
    public string? ReplacedByToken { get; set; }
    public string? IPAddress { get; set; }
    public string? UserAgent { get; set; }
}

