namespace TokenForge.Domain.Interfaces
{
    public interface IGenericRepository
    {
        Task AddAsync<T>(T entity) where T : class;
        Task AddRangeAsync<T>(IEnumerable<T> entities) where T : class;
        Task UpdateAsync<T>(T entity) where T : class;
        Task UpdateRangeAsync<T>(IEnumerable<T> entities) where T : class;
        Task DeleteAsync<T>(T entity) where T : class;
        Task DeleteRangeAsync<T>(IEnumerable<T> entities) where T : class;
        Task<int> SaveChangesAsync();
    }
}
