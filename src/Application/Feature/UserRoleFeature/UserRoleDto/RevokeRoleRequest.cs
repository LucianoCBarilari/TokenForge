namespace Application.Feature.UserRoleFeature.UserRoleDto;

public class UserRoleRevokeInputDto
{
    public Guid UserId { get; set; }
    public Guid RoleId { get; set; }
    public string Reason { get; set; } = string.Empty;
}

public sealed class RevokeRoleRequest : UserRoleRevokeInputDto
{
}
