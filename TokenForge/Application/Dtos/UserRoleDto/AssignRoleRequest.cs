namespace TokenForge.Application.Dtos.UserRoleDto
{
    public class AssignRoleRequest
    {
        public Guid UserId { get; set; }
        public Guid RoleId { get; set; }
    }
}


