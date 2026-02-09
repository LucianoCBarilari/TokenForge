using System.Data;

namespace TokenForge.Application.Dtos.UserDto
{
    public class UserResponse
    {
        public Guid UserId { get; set; }
        public string Email { get; set; } = string.Empty;
        public string UserAccount { get; set; } = string.Empty;
        public bool IsActive { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
    }
}


