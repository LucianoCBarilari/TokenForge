using Application.Abstractions.Persistence;
using Infrastructure.DataAccess;
using Microsoft.EntityFrameworkCore.Storage;

namespace Infrastructure.Ports.Persistence;

public class EfTransactionalUnitOfWork(TokenForgeContext dbContext) : ITransactionalUnitOfWork
{
    private IDbContextTransaction? transaction;

    public bool IsInTransaction => transaction is not null;

    public async Task BeginTransactionAsync(CancellationToken ct = default)
    {
        if (transaction is not null)
            throw new InvalidOperationException("Transaction already open.");

        transaction = await dbContext.Database.BeginTransactionAsync(ct);
    }

    public async Task CommitAsync(CancellationToken ct = default)
    {
        if (transaction is null)
            throw new InvalidOperationException("There is no active transaction to commit.");

        await transaction.CommitAsync(ct);
        await transaction.DisposeAsync();
        transaction = null;
    }

    public async Task RollbackAsync(CancellationToken ct = default)
    {
        if (transaction is null)
            return;

        await transaction.RollbackAsync(ct);
        await transaction.DisposeAsync();
        transaction = null;
    }
}
