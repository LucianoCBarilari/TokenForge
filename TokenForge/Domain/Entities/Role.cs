using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace TokenForge.Domain.Entities
{
    public class Role
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public Guid RolesId { get; set; }
        [Required, MaxLength(100)]
        public string RoleName { get; set; } = string.Empty;
        [MaxLength(256)]
        public string? RoleDescription { get; set; }
        public bool IsActive { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? RevokedAt { get; set; }
        public ICollection<UserRole>? UserRoles { get; set; }
    }
}
