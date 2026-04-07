namespace Application.Feature.RolePermissionFeature;

[Mapper]
public partial class RolePermissionMapper
{
    [MapProperty("Role.RoleName", nameof(RolePermissionResponse.RoleName))]
    [MapProperty("Permission.PermissionCode", nameof(RolePermissionResponse.PermissionCode))]
    [MapProperty("Permission.PermissionName", nameof(RolePermissionResponse.PermissionName))]
    [MapperIgnoreSource(nameof(RolePermission.DeactivatedReason))]
    [MapperIgnoreSource(nameof(RolePermission.DeactivatedAt))]
    [MapperIgnoreSource(nameof(RolePermission.Role))]
    [MapperIgnoreSource(nameof(RolePermission.Permission))]
    public partial RolePermissionResponse ToResponse(RolePermission entity);

    public partial List<RolePermissionResponse> ToResponseList(List<RolePermission> entities);
}
