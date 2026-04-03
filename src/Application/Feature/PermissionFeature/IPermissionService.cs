namespace Application.Feature.PermissionFeature;

public interface IPermissionService
{
    Task<Result<PermissionResponse>> CreatePermissionAsync(PermissionCreateInputDto input, CancellationToken ct = default);
    Task<Result> UpdatePermissionAsync(PermissionUpdateInputDto input, CancellationToken ct = default);
    Task<Result> DeactivatePermissionAsync(Guid permissionId, CancellationToken ct = default);
    Task<Result> ReactivatePermissionAsync(Guid permissionId, CancellationToken ct = default);
    Task<Result<PermissionResponse>> GetPermissionByIdAsync(Guid permissionId, CancellationToken ct = default);
    Task<Result<PermissionResponse>> GetPermissionByCodeAsync(string permissionCode, CancellationToken ct = default);
    Task<Result<List<PermissionResponse>>> GetAllPermissionsAsync(CancellationToken ct = default);
    Task<Result<List<PermissionResponse>>> GetActivePermissionsAsync(CancellationToken ct = default);
}
