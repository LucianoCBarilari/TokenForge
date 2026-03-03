namespace Application.Abstractions.Persistence;

public interface IUserRoleStore
{
    Task<UserRole?> GetAsync(Guid userId, Guid roleId, CancellationToken ct = default);
    Task<UserRole?> GetByIdAsync(Guid userRoleId, CancellationToken ct = default);
    Task<List<UserRole>> GetActiveByUserIdAsync(Guid userId, CancellationToken ct = default);
    Task<List<User>> GetActiveUsersByRoleIdAsync(Guid roleId, CancellationToken ct = default);
    Task AddAsync(UserRole userRole, CancellationToken ct = default);
    void Update(UserRole userRole);
    Task SaveChangesAsync(CancellationToken ct = default);
}
