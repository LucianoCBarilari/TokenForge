namespace Application.Feature.PermissionFeature;

public class PermissionCreateInputDto
{
    public string PermissionCode { get; set; } = string.Empty;
    public string PermissionName { get; set; } = string.Empty;
    public string? PermissionDescription { get; set; }
}
