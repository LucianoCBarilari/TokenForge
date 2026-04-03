namespace Application.Feature.RolePermissionFeature;

public class RevokeRolePermissionInputDto
{
    public Guid RoleId { get; set; }
    public Guid PermissionId { get; set; }
    public string? Reason { get; set; }
}
