namespace Application.Feature.UserRoleFeature.UserRoleDto
{
    public class UserRoleAssignInputDto
    {
        public Guid UserId { get; set; }
        public Guid RoleId { get; set; }
    }

    public class AssignRoleRequest : UserRoleAssignInputDto
    {
    }
}


