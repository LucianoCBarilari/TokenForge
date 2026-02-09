namespace TokenForge.Domain.Interfaces
{
    public interface IUnitOfWork
    {
        Task<int> SaveChangesAsync();
        Task<IDisposable> BeginTransactionAsync();
    }
}
