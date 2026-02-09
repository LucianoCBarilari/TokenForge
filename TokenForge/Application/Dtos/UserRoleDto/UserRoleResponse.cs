namespace TokenForge.Application.Dtos.UserRoleDto
{
    public class UserRoleResponse
    {
        public Guid UserRoleId { get; set; }
        public Guid UserId { get; set; }
        public string UserAccount { get; set; } = string.Empty;
        public Guid RoleId { get; set; }
        public string RoleName { get; set; } = string.Empty; 
        public DateTime AssignedAt { get; set; }
        public bool IsActive { get; set; }
        public DateTime? DeactivatedAt { get; set; }
        public string? DeactivatedReason { get; set; }
    }
}


