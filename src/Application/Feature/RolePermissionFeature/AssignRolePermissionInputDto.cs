namespace Application.Feature.RolePermissionFeature;

public class AssignRolePermissionInputDto
{
    public Guid RoleId { get; set; }
    public Guid PermissionId { get; set; }
}
