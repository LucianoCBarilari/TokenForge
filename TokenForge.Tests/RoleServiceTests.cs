/*using Microsoft.Extensions.Logging;
using Moq;
using TokenForge.Application.Services.UseCases;
using TokenForge.Domain.Entities;
using TokenForge.Domain.Errors;
using TokenForge.Domain.Interfaces;
namespace TokenForge
{
    
    public class RoleServiceTests
    {      

        
        [Fact]
        public async Task GetAllRoles_WhenRepositoryReturnsRoles_ReturnsMappedResponses()
        {
            //Arrange
            var repo = new Mock<IRoleRepository>();
            var logger = new Mock<ILogger<RoleService>>();

            var roles = new List<Role>
            {
                new Role
                {
                    RolesId = Guid.NewGuid(),
                    RoleName = "Admin",
                    RoleDescription = "Full access",
                    IsActive = true,
                    CreatedAt = DateTime.UtcNow
                }
            };

          repo.Setup(r => r.GetAllAsync()).ReturnsAsync(roles);

          var service = new RoleService(repo.Object, logger.Object);

          // Act
          var result = await service.GetAllRoles();

          // Assert
          Assert.True(result.IsSuccess);
          Assert.Single(result.Value);
          Assert.Equal("Admin", result.Value[0].RoleName);
        }
        [Fact]
        public async Task GetAllRoles_WhenNoRoles_ReturnsEmptyList()
        {
            var repo = new Mock<IRoleRepository>();
            var logger = new Mock<ILogger<RoleService>>();
            repo.Setup(r => r.GetAllAsync()).ReturnsAsync(new List<Role>());

            var service = new RoleService(repo.Object, logger.Object);

            var result = await service.GetAllRoles();

            Assert.True(result.IsSuccess);
            Assert.Empty(result.Value);
        }

        [Fact]
        public async Task GetAllRoles_WhenRepositoryThrows_ReturnsOperationFailed()
        {
            var repo = new Mock<IRoleRepository>();
            var logger = new Mock<ILogger<RoleService>>();
            repo.Setup(r => r.GetAllAsync()).ThrowsAsync(new Exception("db"));

            var service = new RoleService(repo.Object, logger.Object);

            var result = await service.GetAllRoles();

            Assert.True(result.IsFailure);
            Assert.Equal(RoleErrors.OperationFailed.Code, result.Error.Code);
        }

        [Fact]
        public async Task GetAllRoles_WhenRoleHasNulls_DoesNotThrow()
        {
            var repo = new Mock<IRoleRepository>();
            var logger = new Mock<ILogger<RoleService>>();
            repo.Setup(r => r.GetAllAsync()).ReturnsAsync(new List<Role>
            {
                new Role { RolesId = Guid.NewGuid(), RoleName = null, RoleDescription = null }
            });

            var service = new RoleService(repo.Object, logger.Object);

            var result = await service.GetAllRoles();

            Assert.True(result.IsSuccess);
            Assert.Single(result.Value);
    
        }

        //GetRoleById
        // 1. Caso exitoso principal
        [Fact]
        public async Task GetRoleById_ValidId_ReturnsRole() { }
        // 2. Casos de error de negocio
        [Fact]
        public async Task GetRoleById_IdNotFound_ThrowsNotFoundException() { }
        [Fact]
        public async Task GetRoleById_InvalidIdFormat_ThrowsValidationException() { }
        [Fact]
        public async Task GetRoleById_NullId_ThrowsArgumentNullException() { }
        // 3. Casos de infraestructura/errores t�cnicos  
        [Fact]
        public async Task GetRoleById_RepositoryFails_ThrowsDataAccessException() { }
        // 4. Casos borde (si aplican)
        [Fact]
        public async Task GetRoleById_RoleWithNullProperties_ReturnsRole() { }
        //UpdateRole
        // 1. �xito
        [Fact]
        public async Task UpdateRole_ValidData_ReturnsUpdatedRole() { }

        // 2. Validaciones
        [Fact]
        public async Task UpdateRole_NullData_ThrowsArgumentNullException() { }
        [Fact]
        public async Task UpdateRole_InvalidId_ThrowsValidationException() { }

        // 3. Reglas negocio
        [Fact]
        public async Task UpdateRole_RoleNotFound_ThrowsNotFoundException() { }
        [Fact]
        public async Task UpdateRole_DuplicateName_ThrowsBusinessRuleException() { }

        // 4. Comportamiento
        [Fact]
        public async Task UpdateRole_PartialUpdate_UpdatesOnlyChangedFields() { }

        // 5. Errores t�cnicos
        [Fact]
        public async Task UpdateRole_RepositoryFails_ThrowsDataAccessException() { }

        // 6. Caso borde
        [Fact]
        public async Task UpdateRole_ConcurrentModification_HandlesCorrectly() { }
        //GetRolesForUserAsync

        // 1. �xito b�sico
        [Fact]
        public async Task GetRolesForUserAsync_ValidUser_ReturnsRoleList() { }

        // 2. Validaciones entrada
        [Fact]
        public async Task GetRolesForUserAsync_NullUserId_ThrowsArgumentNullException() { }
        [Fact]
        public async Task GetRolesForUserAsync_InvalidUserId_ThrowsValidationException() { }

        // 3. Estados de usuario
        [Fact]
        public async Task GetRolesForUserAsync_UserWithoutRoles_ReturnsEmptyList() { }
        [Fact]
        public async Task GetRolesForUserAsync_UserNotFound_ReturnsEmptyList() { }// o Throws

        // 4. Comportamiento datos
        [Fact]
        public async Task GetRolesForUserAsync_MultipleRoles_ReturnsAllRoles() { }
        [Fact]
        public async Task GetRolesForUserAsync_OnlyActiveRoles_ReturnsFilteredList() { }

        // 5. Error t�cnico
        [Fact]
        public async Task GetRolesForUserAsync_DatabaseError_ThrowsDataAccessException() { }

        // 6. Transformaci�n (si aplica)
        [Fact]
        public async Task GetRolesForUserAsync_ReturnsProperlyMappedDtos() { }

    }
}*/

