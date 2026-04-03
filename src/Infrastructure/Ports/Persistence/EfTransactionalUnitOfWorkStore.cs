using Application.Abstractions.Persistence;
using Infrastructure.DataAccess;
using Microsoft.EntityFrameworkCore.Storage;

namespace Infrastructure.Ports.Persistence;

public class EfTransactionalUnitOfWorkEfRoleStore : ITransactionalUnitOfWork
{
    private readonly TokenForgeContext dbContext;
    private IDbContextTransaction? transaction;

    public EfTransactionalUnitOfWorkEfRoleStore(TokenForgeContext context)
    {
        dbContext= context;
    }
    public bool IsInTransaction => transaction != null;

    public async Task BeginTransactionAsync(CancellationToken ct = default)
    {
        if (transaction != null) throw new InvalidOperationException("Transaction already open.");
        transaction = await dbContext.Database.BeginTransactionAsync(ct);
    }

    public async Task CommitAsync(CancellationToken ct = default)
    {
        if (transaction == null)
            throw new InvalidOperationException("There is no active transaction to commit.");

        await transaction.CommitAsync(ct);
        transaction.Dispose();
        transaction = null;
    }

    public async Task RollbackAsync(CancellationToken ct = default)
    {
        if (transaction == null) return;

        await transaction.RollbackAsync(ct);
        transaction.Dispose();
        transaction = null;
    }
}
