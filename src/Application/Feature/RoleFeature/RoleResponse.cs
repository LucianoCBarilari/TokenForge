namespace Application.Feature.RoleFeature
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


