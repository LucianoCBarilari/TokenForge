namespace Domain.Entities;

public class LoginAttempt
{
    public Guid LoginAttemptID { get; set; }
    public string UserAttempt { get; set; } = string.Empty;
    public Guid UserId { get; set; }
    public User? User { get; set; }
    public int FailedAttempts { get; set; }
    public DateTime LastAttemptAt { get; set; }
    public DateTime? LockedUntil { get; set; }
}

