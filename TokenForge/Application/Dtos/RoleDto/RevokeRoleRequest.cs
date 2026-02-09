namespace TokenForge.Application.Dtos.RoleDto
{
    public class RevokeRoleRequest
    {
        public Guid UserId { get; set; }
        public Guid RoleId { get; set; }
        public string Reason { get; set; } = string.Empty;
    }
}


