using System.ComponentModel.DataAnnotations;

namespace TokenForge.Application.Dtos.RoleDto
{
    public class RoleResponse
    {
        public Guid RolesId { get; set; }
        public string RoleName { get; set; } = string.Empty;
        public string? RoleDescription { get; set; }
        public bool IsActive { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}


