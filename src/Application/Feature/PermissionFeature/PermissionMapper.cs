namespace Application.Feature.PermissionFeature;

[Mapper]
public partial class PermissionMapper
{
    [MapperIgnoreSource(nameof(PermissionCreateInputDto.PermissionCode))]
    [MapperIgnoreTarget(nameof(Permission.PermissionId))]
    [MapperIgnoreTarget(nameof(Permission.IsActive))]
    [MapperIgnoreTarget(nameof(Permission.CreatedAt))]
    [MapperIgnoreTarget(nameof(Permission.RevokedAt))]
    [MapperIgnoreTarget(nameof(Permission.RolePermissions))]
    public partial Permission ToEntity(PermissionCreateInputDto dto);

    [MapperIgnoreTarget(nameof(Permission.PermissionId))]
    [MapperIgnoreTarget(nameof(Permission.PermissionCode))]
    [MapperIgnoreTarget(nameof(Permission.IsActive))]
    [MapperIgnoreTarget(nameof(Permission.CreatedAt))]
    [MapperIgnoreTarget(nameof(Permission.RevokedAt))]
    [MapperIgnoreTarget(nameof(Permission.RolePermissions))]
    public partial void ApplyUpdate(PermissionUpdateInputDto dto, Permission entity);

    public partial PermissionResponse ToResponse(Permission entity);
    public partial List<PermissionResponse> ToResponseList(List<Permission> entities);
}
