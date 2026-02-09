using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace TokenForge.Domain.Entities
{
    public class UserRole
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public Guid UserRoleId { get; set; }
        [ForeignKey(nameof(User))]
        public Guid UserId { get; set; }
        public User? User { get; set; }
        [ForeignKey(nameof(Role))]
        public Guid RoleId { get; set; }
        public Role? Role { get; set; }
        public DateTime AssignedAt { get; set; }
        public bool IsActive { get; set; }
        public DateTime? DeactivatedAt { get; set; }
        [MaxLength(256)]
        public string? DeactivatedReason { get; set; }
    }
}
