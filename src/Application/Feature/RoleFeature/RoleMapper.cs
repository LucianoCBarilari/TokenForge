namespace Application.Feature.RoleFeature;

[Mapper]
public partial class RoleMapper
{
    [MapperIgnoreSource(nameof(RoleInputDto.RolesId))]
    [MapperIgnoreTarget(nameof(Role.IsActive))]
    [MapperIgnoreTarget(nameof(Role.CreatedAt))]
    [MapperIgnoreTarget(nameof(Role.RevokedAt))]
    [MapperIgnoreTarget(nameof(Role.UserRoles))]
    [MapperIgnoreTarget(nameof(Role.RolePermissions))]
    public partial Role ToEntity(RoleInputDto dto);
    public partial RoleResponse ToResponse(Role entity);
    [MapperIgnoreTarget(nameof(Role.RolesId))]
    [MapperIgnoreTarget(nameof(Role.CreatedAt))]
    [MapperIgnoreTarget(nameof(Role.RevokedAt))]
    [MapperIgnoreTarget(nameof(Role.UserRoles))]
    [MapperIgnoreTarget(nameof(Role.RolePermissions))]
    public partial void ApplyUpdate(RoleInputDto dto, Role entity);
    public partial List<RoleResponse> ToResponseList(List<Role> entities);
}
