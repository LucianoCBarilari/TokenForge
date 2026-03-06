namespace Infrastructure.DataAccess.Seeds;

public static class AuthSeedIds
{
    public static readonly Guid AdminRoleId = Guid.Parse("4D2D7AF9-2C7F-4F42-8A3D-7E7E26A6A001");
    public static readonly Guid ManagerRoleId = Guid.Parse("4D2D7AF9-2C7F-4F42-8A3D-7E7E26A6A002");
    public static readonly Guid UserRoleId = Guid.Parse("4D2D7AF9-2C7F-4F42-8A3D-7E7E26A6A003");

    public static readonly Guid PermissionTokensRevokeCurrentId = Guid.Parse("7CC9D620-07C7-40D2-A5A7-95E0D1C0B101");
    public static readonly Guid PermissionTokensRevokeAllId = Guid.Parse("7CC9D620-07C7-40D2-A5A7-95E0D1C0B102");
    public static readonly Guid PermissionUsersReadId = Guid.Parse("7CC9D620-07C7-40D2-A5A7-95E0D1C0B103");
    public static readonly Guid PermissionUsersWriteId = Guid.Parse("7CC9D620-07C7-40D2-A5A7-95E0D1C0B104");
    public static readonly Guid PermissionRolesReadId = Guid.Parse("7CC9D620-07C7-40D2-A5A7-95E0D1C0B105");
    public static readonly Guid PermissionRolesWriteId = Guid.Parse("7CC9D620-07C7-40D2-A5A7-95E0D1C0B106");
    public static readonly Guid PermissionUserRolesAssignId = Guid.Parse("7CC9D620-07C7-40D2-A5A7-95E0D1C0B107");
    public static readonly Guid PermissionUserRolesRevokeId = Guid.Parse("7CC9D620-07C7-40D2-A5A7-95E0D1C0B108");
}
