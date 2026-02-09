using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace TokenForge.Domain.Entities
{
    public class RefreshToken
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public Guid RefreshTokensId { get; set; }
        [Required, MaxLength(512)]
        public string Token { get; set; } = string.Empty;
        [ForeignKey(nameof(User))]
        public Guid UserId { get; set; }
        public User? User { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public DateTime? RevokedAt { get; set; }
        [MaxLength(512)]
        public string? ReplacedByToken { get; set; }
        [MaxLength(45)]
        public string? IPAddress { get; set; }
        [MaxLength(256)]
        public string? UserAgent { get; set; }
    }
}
