using Application.Feature.UserFeature.UserDto;

namespace Application.Feature.UserFeature;

[Mapper]
public partial class UserMapper
{
    [MapperIgnoreSource(nameof(UserCreateInputDto.Password))]
    [MapperIgnoreSource(nameof(UserCreateInputDto.RoleId))]
    [MapperIgnoreTarget(nameof(User.UsersId))]
    [MapperIgnoreTarget(nameof(User.PasswordHash))]
    [MapperIgnoreTarget(nameof(User.IsActive))]
    [MapperIgnoreTarget(nameof(User.CreatedAt))]
    [MapperIgnoreTarget(nameof(User.UpdatedAt))]
    [MapperIgnoreTarget(nameof(User.RefreshTokens))]
    [MapperIgnoreTarget(nameof(User.UserRoles))]
    public partial User ToEntity(UserCreateInputDto input);

    [MapProperty(nameof(User.UsersId), nameof(UserResponse.UserId))]
    public partial UserResponse ToResponse(User entity);

    public partial List<UserResponse> ToResponseList(List<User> entities);

    [MapProperty(nameof(User.UsersId), nameof(UserWithRolesResponse.UserId))]
    [MapperIgnoreTarget(nameof(UserWithRolesResponse.Roles))]
    public partial UserWithRolesResponse ToWithRolesResponse(User entity);
}
