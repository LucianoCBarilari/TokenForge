namespace Application.Feature.RolePermissionFeature;

[Mapper]
public partial class RolePermissionMapper
{
    [MapProperty("Role.RoleName", nameof(RolePermissionResponse.RoleName))]
    [MapProperty("Permission.PermissionCode", nameof(RolePermissionResponse.PermissionCode))]
    [MapProperty("Permission.PermissionName", nameof(RolePermissionResponse.PermissionName))]
    public partial RolePermissionResponse ToResponse(RolePermission entity);

    public partial List<RolePermissionResponse> ToResponseList(List<RolePermission> entities);
}
