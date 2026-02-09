using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace TokenForge.Domain.Entities
{
    public class LoginAttempt
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public Guid LoginAttemptID { get; set; }
        [Required, MaxLength(100)]
        public string UserAttempt { get; set; } = string.Empty;
        [ForeignKey(nameof(User))]
        public Guid UserId { get; set; }
        public User? User { get; set; }
        public int FailedAttempts { get; set; }
        public DateTime LastAttemptAt { get; set; }
        public DateTime? LockedUntil { get; set; }
    }
}
