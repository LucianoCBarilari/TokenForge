namespace Application.Abstractions.Persistence;

public interface IRoleStore
{
    Task<Role?> GetByIdAsync(Guid roleId, CancellationToken ct = default);
    Task<List<Role>> GetAllAsync(CancellationToken ct = default);
    Task<List<Role>> GetByIdsAsync(IEnumerable<Guid> roleIds, CancellationToken ct = default);
    void Update(Role role);
    Task SaveChangesAsync(CancellationToken ct = default);
}
