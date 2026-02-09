using Microsoft.EntityFrameworkCore;
using TokenForge.Domain.Interfaces;
using TokenForge.Infrastructure.Persistence.DataAccess;

namespace TokenForge.Infrastructure.Persistence.Repositories
{
    public class GenericRepository(TokenForgeContext securityContext) : IGenericRepository
    {
        private readonly TokenForgeContext _context = securityContext;

        /// <summary>
        /// Adds a new entity of generic type T to the database.
        /// </summary>
        /// <typeparam name="T">Entity type</typeparam>
        /// <param name="entity">Entity to add</param>
        /// <returns>Boolean indicating the success of the operation</returns>
        public async Task<bool> AddAsync<T>(T entity) where T : class
        {
            _context.Set<T>().Add(entity);
            return await _context.SaveChangesAsync() > 0;
        }
        /// <summary>
        /// Updates an existing entity of generic type T in the database.
        /// </summary>
        /// <typeparam name="T">Entity type</typeparam>
        /// <param name="entity">Entity to update</param>
        /// <returns>Boolean indicating the success of the operation</returns>
        public async Task<bool> UpdateAsync<T>(T entity) where T : class
        {
            _context.Set<T>().Update(entity);
            return await _context.SaveChangesAsync() > 0;
        }
        /// <summary>
        /// Deletes an entity of generic type T from the database based on an identifier.
        /// </summary>
        /// <typeparam name="T">Entity type</typeparam>
        /// <param name="id">Identifier of the entity to delete</param>
        /// <returns>Boolean indicating the success of the operation</returns>
        public async Task<bool> DeleteAsync<T>(Guid id) where T : class
        {
            var entity = await _context.Set<T>().FindAsync(id);
            if (entity == null)
            {
                return false;
            }

            _context.Set<T>().Remove(entity);
            return await _context.SaveChangesAsync() > 0;
        }
        /// <summary>
        /// Gets an entity of generic type T from the database based on an identifier.
        /// </summary>
        /// <typeparam name="T">Entity type</typeparam>
        /// <param name="id">Identifier of the entity to get</param>
        /// <returns>Asynchronous task that returns the found entity</returns>
        public async Task<T?> GetByIdAsync<T>(Guid id) where T : class
        {
            return await _context.Set<T>().FindAsync(id);
        }
        /// <summary>
        /// Gets all entities of generic type T from the database.
        /// </summary>
        /// <typeparam name="T">Entity type</typeparam>
        /// <returns>Asynchronous task that returns a list of all entities</returns>
        public async Task<List<T>> GetAllAsync<T>() where T : class
        {
            return await _context.Set<T>().ToListAsync();
        }
        /// <summary>
        /// Deletes all entities of a given type from the database.
        /// </summary>
        /// <typeparam name="T">The entity type to delete.</typeparam>
        /// <returns>A boolean indicating whether the operation was successful.</returns>
        public async Task<bool> DeleteAllAsync<T>() where T : class
        {
            var entities = _context.Set<T>();
            _context.Set<T>().RemoveRange(entities);
            return await _context.SaveChangesAsync() > 0;
        }
    }
}



