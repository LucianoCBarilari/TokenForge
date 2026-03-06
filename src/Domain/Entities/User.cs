namespace Domain.Entities;

public class User
{
    public Guid UsersId { get; set; }
    public string Email { get; set; } = string.Empty;
    public string UserAccount { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public bool IsActive { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? UpdatedAt { get; set; }
    public ICollection<RefreshToken>? RefreshTokens { get; set; }
    public ICollection<UserRole>? UserRoles { get; set; }
}

