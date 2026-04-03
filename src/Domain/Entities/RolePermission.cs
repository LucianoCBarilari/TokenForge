namespace Domain.Entities;

public class RolePermission
{
    public Guid RolePermissionId { get; set; }
    public Guid RoleId { get; set; }
    public Role? Role { get; set; }
    public Guid PermissionId { get; set; }
    public Permission? Permission { get; set; }
    public DateTime AssignedAt { get; set; }
    public bool IsActive { get; set; }
    public DateTime? DeactivatedAt { get; set; }
    public string? DeactivatedReason { get; set; }
}
