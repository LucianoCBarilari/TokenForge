namespace Application.Abstractions.Persistence;

public interface IRolePermissionStore
{
    Task<RolePermission?> GetAsync(Guid roleId, Guid permissionId, CancellationToken ct = default);
    Task<List<RolePermission>> GetActiveByRoleIdAsync(Guid roleId, CancellationToken ct = default);
    Task<List<RolePermission>> GetActiveByPermissionIdAsync(Guid permissionId, CancellationToken ct = default);
    Task<List<Guid>> GetActivePermissionIdsByRoleIdAsync(Guid roleId, CancellationToken ct = default);
    Task AddAsync(RolePermission rolePermission, CancellationToken ct = default);
    Task AddRangeAsync(IEnumerable<RolePermission> rolePermissions, CancellationToken ct = default);
    void Update(RolePermission rolePermission);
    void UpdateRange(IEnumerable<RolePermission> rolePermissions);
    Task SaveChangesAsync(CancellationToken ct = default);
}
