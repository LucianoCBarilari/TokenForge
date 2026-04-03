namespace Application.Feature.RolePermissionFeature;

public class SyncRolePermissionsInputDto
{
    public Guid RoleId { get; set; }
    public List<Guid> PermissionIds { get; set; } = [];
}
