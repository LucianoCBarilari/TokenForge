namespace Application.Feature.RolePermissionFeature;

public interface IRolePermissionService
{
    Task<Result> AssignPermissionToRoleAsync(AssignRolePermissionInputDto input, CancellationToken ct = default);
    Task<Result> RevokePermissionFromRoleAsync(RevokeRolePermissionInputDto input, CancellationToken ct = default);
    Task<Result> SyncRolePermissionsAsync(SyncRolePermissionsInputDto input, CancellationToken ct = default);
    Task<Result<List<RolePermissionResponse>>> GetPermissionsByRoleAsync(Guid roleId, CancellationToken ct = default);
    Task<Result<List<RolePermissionResponse>>> GetRolesByPermissionAsync(Guid permissionId, CancellationToken ct = default);
}
