namespace Application.Feature.UserRoleFeature.UserRoleDto
{
    public class UserRoleSummaryResponse
    {
        public Guid UserRoleId { get; set; }
        public Guid UserId { get; set; }
        public Guid RoleId { get; set; }
        public DateTime AssignedAt { get; set; }
        public bool IsActive { get; set; } = true;
        public DateTime? DeactivatedAt { get; set; }
        public string? DeactivatedReason { get; set; }
    }
}


