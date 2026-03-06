namespace Application.Feature.RoleFeature;

[Mapper]
public partial class RoleMapper
{
    [MapperIgnoreSource(nameof(RoleInputDto.RolesId))]
    public partial Role ToEntity(RoleInputDto dto);
    public partial RoleResponse ToResponse(Role entity);
    [MapperIgnoreTarget(nameof(Role.RolesId))]
    public partial void ApplyUpdate(RoleInputDto dto, Role entity);
    public partial List<RoleResponse> ToResponseList(List<Role> entities);
}
