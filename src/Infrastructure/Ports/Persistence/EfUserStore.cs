using Application.Abstractions.Persistence;
using Domain.Entities;
using Infrastructure.DataAccess;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Ports.Persistence;

public sealed class EfUserStore(TokenForgeContext dbContext) : IUserStore
{
    public async Task<User?> GetByIdAsync(Guid userId, CancellationToken ct = default)
    {
        return await dbContext.Users.FirstOrDefaultAsync(x => x.UsersId == userId, ct);
    }

    public async Task<User?> GetByAccountAsync(string account, CancellationToken ct = default)
    {
        return await dbContext.Users.FirstOrDefaultAsync(x => x.UserAccount == account, ct);
    }

    public async Task<bool> ExistsByEmailAsync(string email, CancellationToken ct = default)
    {
        return await dbContext.Users.AnyAsync(x => x.Email == email, ct);
    }

    public async Task<bool> ExistsByAccountAsync(string account, CancellationToken ct = default)
    {
        return await dbContext.Users.AnyAsync(x => x.UserAccount == account, ct);
    }

    public async Task<List<User>> GetActiveAsync(CancellationToken ct = default)
    {
        return await dbContext.Users
            .AsNoTracking()
            .Where(x => x.IsActive)
            .ToListAsync(ct);
    }

    public async Task AddAsync(User user, CancellationToken ct = default)
    {
        await dbContext.Users.AddAsync(user, ct).AsTask();
    }

    public void Update(User user)
    {
        dbContext.Users.Update(user);
    }

    public Task SaveChangesAsync(CancellationToken ct = default)
    {
        return dbContext.SaveChangesAsync(ct);
    }
}
