namespace Application.Feature.PermissionFeature;

public class PermissionUpdateInputDto
{
    public Guid PermissionId { get; set; }
    public string? PermissionName { get; set; }
    public string? PermissionDescription { get; set; }
}
