namespace Application.Feature.UserRoleFeature;

[Mapper]
public partial class UserRoleMapper
{
    [MapProperty("User.UserAccount", nameof(UserRoleResponse.UserAccount))]
    [MapProperty("Role.RoleName", nameof(UserRoleResponse.RoleName))]
    public partial UserRoleResponse ToResponse(UserRole entity);

    public partial List<UserRoleResponse> ToResponseList(List<UserRole> entities);
}
