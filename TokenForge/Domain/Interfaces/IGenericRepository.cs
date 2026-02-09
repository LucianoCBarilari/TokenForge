namespace TokenForge.Domain.Interfaces
{
    public interface IGenericRepository
    {
        public Task<bool> AddAsync<T>(T entity) where T : class;
        public Task<bool> UpdateAsync<T>(T entity) where T : class;
        public Task<bool> DeleteAsync<T>(Guid Id) where T : class;
        public Task<T?> GetByIdAsync<T>(Guid Id) where T : class;
        public Task<List<T>> GetAllAsync<T>() where T : class;
        public Task<bool> DeleteAllAsync<T>() where T : class;
    }
}

