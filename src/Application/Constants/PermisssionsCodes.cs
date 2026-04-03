namespace Application.Constants;

public static class PermissionCodes
{
    public const string AuthLogin = "auth.login";
    public const string AuthLogout = "auth.logout";

    public const string TokensValidate = "tokens.validate";
    public const string TokensRefresh = "tokens.refresh";
    public const string TokensRevokeCurrent = "tokens.revoke.current";
    public const string TokensRevokeAll = "tokens.revoke.all";

    public const string UsersRead = "users.read";
    public const string UsersWrite = "users.write";
    public const string UsersCreate = "users.create";
    public const string UsersUpdateEmail = "users.update.email";
    public const string UsersUpdateAccount = "users.update.account";
    public const string UsersUpdatePassword = "users.update.password";
    public const string UsersDisable = "users.disable";
    public const string UsersReadRoles = "users.read.roles";

    public const string RolesRead = "roles.read";
    public const string RolesWrite = "roles.write";
    public const string RolesUpdate = "roles.update";
    public const string RolesReadUsers = "roles.read.users";

    public const string PermissionsRead = "permissions.read";
    public const string PermissionsCreate = "permissions.create";
    public const string PermissionsUpdate = "permissions.update";
    public const string PermissionsActivate = "permissions.activate";
    public const string PermissionsDeactivate = "permissions.deactivate";

    public const string RolePermissionsAssign = "rolepermissions.assign";
    public const string RolePermissionsRevoke = "rolepermissions.revoke";
    public const string RolePermissionsSync = "rolepermissions.sync";
    public const string RolePermissionsRead = "rolepermissions.read";

    public const string UserRolesAssign = "userroles.assign";
    public const string UserRolesRevoke = "userroles.revoke";
    public const string UserRolesRead = "userroles.read";


    public static IReadOnlyCollection<string> GetAll()
    {
        return
        [
               AuthLogin,
               AuthLogout,

               TokensValidate,
               TokensRefresh,
               TokensRevokeCurrent,
               TokensRevokeAll,

               UsersRead,
               UsersWrite,
               UsersCreate,
               UsersUpdateEmail,
               UsersUpdateAccount,
               UsersUpdatePassword,
               UsersDisable,
               UsersReadRoles,

               RolesRead,
               RolesWrite,
               RolesUpdate,
               RolesReadUsers,

               PermissionsRead,
               PermissionsCreate,
               PermissionsUpdate,
               PermissionsActivate,
               PermissionsDeactivate,

               RolePermissionsAssign,
               RolePermissionsRevoke,
               RolePermissionsSync,
               RolePermissionsRead,

               UserRolesAssign,
               UserRolesRevoke,
               UserRolesRead,

        ];
    }
}
