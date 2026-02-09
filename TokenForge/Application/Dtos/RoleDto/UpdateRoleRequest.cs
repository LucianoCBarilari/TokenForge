using System.ComponentModel.DataAnnotations;

namespace TokenForge.Application.Dtos.RoleDto
{
    public class UpdateRoleRequest
    { 
        public Guid RolesId { get; set; }        
        public string? RoleName { get; set; }        
        public string? RoleDescription { get; set; }
        public bool? IsActive { get; set; }
    }
}


