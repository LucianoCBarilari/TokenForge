namespace Application.Feature.RoleFeature;

public class RoleInputDto
{
    public Guid RolesId { get; set; }
    public string? RoleName { get; set; }
    public string? RoleDescription { get; set; }
    public bool? IsActive { get; set; }
}


