namespace Application.Abstractions.Persistence;

public interface IPermissionStore
{
    Task<Permission?> GetByIdAsync(Guid permissionId, CancellationToken ct = default);
    Task<Permission?> GetByCodeAsync(string permissionCode, CancellationToken ct = default);
    Task<List<Permission>> GetAllAsync(CancellationToken ct = default);
    Task<List<Permission>> GetActiveAsync(CancellationToken ct = default);
    Task AddAsync(Permission permission, CancellationToken ct = default);
    void Update(Permission permission);
    Task SaveChangesAsync(CancellationToken ct = default);
}
