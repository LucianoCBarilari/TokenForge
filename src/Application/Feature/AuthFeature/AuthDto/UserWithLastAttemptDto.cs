namespace Application.Feature.AuthFeature.AuthDto;

public class UserWithLastAttemptDto
{
    public Guid UsersId { get; set; }
    public string UserAccount { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public bool IsActive { get; set; }

    public int? FailedAttempts { get; set; }
    public DateTime? LastAttemptAt { get; set; }
    public DateTime? LockedUntil { get; set; }
}
