using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace TokenForge.Domain.Entities
{
    public class User
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public Guid UsersId { get; set; }
        [Required, MaxLength(256), EmailAddress]
        public string Email { get; set; } = string.Empty;
        [Required, MaxLength(100)]
        public string UserAccount { get; set; } = string.Empty;
        [Required]
        public string PasswordHash { get; set; } = string.Empty;
        public bool IsActive { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
        public ICollection<RefreshToken>? RefreshTokens { get; set; }
        public ICollection<UserRole>? UserRoles { get; set; }
    }
}
