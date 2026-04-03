namespace Application.Constants;

public static class CustomClaimTypes
{
    /// <summary>
    /// Custom claim type used for granular permissions
    /// Example: "users:read", "orders:approve", "products:delete"
    /// </summary>
    public const string Permission = "permission";

    // You can add more custom claims later if needed
    // public const string TenantId = "tenant_id";
    // public const string DeviceId = "device_id";
}
