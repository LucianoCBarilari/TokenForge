namespace Application.Abstractions.Persistence;

public interface IUserStore
{
    Task<User?> GetByIdAsync(Guid userId, CancellationToken ct = default);
    Task<User?> GetByAccountAsync(string account, CancellationToken ct = default);
    Task<bool> ExistsByEmailAsync(string email, CancellationToken ct = default);
    Task<bool> ExistsByAccountAsync(string account, CancellationToken ct = default);
    Task<List<User>> GetActiveAsync(CancellationToken ct = default);
    Task AddAsync(User user, CancellationToken ct = default);
    void Update(User user);
    Task SaveChangesAsync(CancellationToken ct = default);
}
