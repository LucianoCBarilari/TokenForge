using TokenForge.Domain.Entities;

namespace TokenForge.Application.Dtos.UserDto
{
    public class UserWithRolesResponse
    {
        public Guid UserId { get; set; }
        public string Email { get; set; } = string.Empty;
        public string UserAccount { get; set; } = string.Empty;
        public bool IsActive { get; set; }
        public List<Role> Roles { get; set; } = new();
    }
}


