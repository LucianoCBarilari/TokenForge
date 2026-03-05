namespace Domain.Entities;

public class Role
{
    public Guid RolesId { get; set; }
    public string RoleName { get; set; } = string.Empty;
    public string? RoleDescription { get; set; }
    public bool IsActive { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? RevokedAt { get; set; }
    public ICollection<UserRole>? UserRoles { get; set; }
}

