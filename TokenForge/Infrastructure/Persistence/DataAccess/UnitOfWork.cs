using Microsoft.EntityFrameworkCore.Storage;
using TokenForge.Application.Interfaces;

namespace TokenForge.Infrastructure.Persistence.DataAccess
{
    public class UnitOfWork(TokenForgeContext context) : IUnitOfWork
    {
        private readonly TokenForgeContext _context = context;

        public async Task<ITransaction> BeginTransactionAsync(CancellationToken cancellationToken = default)
        {
            var transaction = await _context.Database.BeginTransactionAsync(cancellationToken);
            return new EfTransaction(transaction);
        }

        public Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            return _context.SaveChangesAsync(cancellationToken);
        }

        private sealed class EfTransaction(IDbContextTransaction transaction) : ITransaction
        {
            private readonly IDbContextTransaction _transaction = transaction;

            public Task CommitAsync(CancellationToken cancellationToken = default)
            {
                return _transaction.CommitAsync(cancellationToken);
            }

            public Task RollbackAsync(CancellationToken cancellationToken = default)
            {
                return _transaction.RollbackAsync(cancellationToken);
            }

            public ValueTask DisposeAsync()
            {
                return _transaction.DisposeAsync();
            }
        }
    }
}


