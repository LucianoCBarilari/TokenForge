using Application.Abstractions.Common;

namespace Application.Feature.RolePermissionFeature;

public class RolePermissionService(
    IRoleStore roleStore,
    IPermissionStore permissionStore,
    IRolePermissionStore rolePermissionStore,
    IClock clock,
    RolePermissionMapper mapper) : IRolePermissionService
{
    public async Task<Result> AssignPermissionToRoleAsync(AssignRolePermissionInputDto input, CancellationToken ct = default)
    {
        var role = await roleStore.GetByIdAsync(input.RoleId, ct);
        if (role is null)
            return Result.Failure(RolePermissionErrors.RoleNotFound);

        var permission = await permissionStore.GetByIdAsync(input.PermissionId, ct);
        if (permission is null)
            return Result.Failure(RolePermissionErrors.PermissionNotFound);

        var current = await rolePermissionStore.GetAsync(input.RoleId, input.PermissionId, ct);
        if (current is not null)
        {
            if (current.IsActive)
                return Result.Failure(RolePermissionErrors.RolePermissionAlreadyExists);

            current.IsActive = true;
            current.DeactivatedAt = null;
            current.DeactivatedReason = null;
            rolePermissionStore.Update(current);
            await rolePermissionStore.SaveChangesAsync(ct);
            return Result.Success();
        }

        await rolePermissionStore.AddAsync(new RolePermission
        {
            RolePermissionId = Guid.NewGuid(),
            RoleId = input.RoleId,
            PermissionId = input.PermissionId,
            AssignedAt = clock.UtcNow,
            IsActive = true
        }, ct);

        await rolePermissionStore.SaveChangesAsync(ct);
        return Result.Success();
    }

    public async Task<Result> RevokePermissionFromRoleAsync(RevokeRolePermissionInputDto input, CancellationToken ct = default)
    {
        var rolePermission = await rolePermissionStore.GetAsync(input.RoleId, input.PermissionId, ct);
        if (rolePermission is null || !rolePermission.IsActive)
            return Result.Failure(RolePermissionErrors.RolePermissionNotFound);

        rolePermission.IsActive = false;
        rolePermission.DeactivatedAt = clock.UtcNow;
        rolePermission.DeactivatedReason = input.Reason;

        rolePermissionStore.Update(rolePermission);
        await rolePermissionStore.SaveChangesAsync(ct);
        return Result.Success();
    }

    public async Task<Result> SyncRolePermissionsAsync(SyncRolePermissionsInputDto input, CancellationToken ct = default)
    {
        var role = await roleStore.GetByIdAsync(input.RoleId, ct);
        if (role is null)
            return Result.Failure(RolePermissionErrors.RoleNotFound);

        var desiredPermissionIds = input.PermissionIds.Distinct().ToList();
        var activePermissionIds = await rolePermissionStore.GetActivePermissionIdsByRoleIdAsync(input.RoleId, ct);

        var toDeactivate = activePermissionIds.Except(desiredPermissionIds).ToHashSet();
        var toAdd = desiredPermissionIds.Except(activePermissionIds).ToHashSet();

        if (toDeactivate.Count > 0)
        {
            var activeRolePermissions = await rolePermissionStore.GetActiveByRoleIdAsync(input.RoleId, ct);
            var revokeNow = clock.UtcNow;
            foreach (var rp in activeRolePermissions.Where(x => toDeactivate.Contains(x.PermissionId)))
            {
                rp.IsActive = false;
                rp.DeactivatedAt = revokeNow;
                rp.DeactivatedReason = "Role permission sync";
            }
            rolePermissionStore.UpdateRange(activeRolePermissions.Where(x => toDeactivate.Contains(x.PermissionId)));
        }

        if (toAdd.Count > 0)
        {
            var permissions = await permissionStore.GetAllAsync(ct);
            var existingPermissionIds = permissions.Select(p => p.PermissionId).ToHashSet();
            if (toAdd.Any(pid => !existingPermissionIds.Contains(pid)))
                return Result.Failure(RolePermissionErrors.PermissionNotFound);

            var now = clock.UtcNow;
            var newRolePermissions = toAdd.Select(permissionId => new RolePermission
            {
                RolePermissionId = Guid.NewGuid(),
                RoleId = input.RoleId,
                PermissionId = permissionId,
                AssignedAt = now,
                IsActive = true
            });

            await rolePermissionStore.AddRangeAsync(newRolePermissions, ct);
        }

        await rolePermissionStore.SaveChangesAsync(ct);
        return Result.Success();
    }

    public async Task<Result<List<RolePermissionResponse>>> GetPermissionsByRoleAsync(Guid roleId, CancellationToken ct = default)
    {
        var role = await roleStore.GetByIdAsync(roleId, ct);
        if (role is null)
            return Result<List<RolePermissionResponse>>.Failure(RolePermissionErrors.RoleNotFound);

        var rolePermissions = await rolePermissionStore.GetActiveByRoleIdAsync(roleId, ct);
        return Result<List<RolePermissionResponse>>.Success(mapper.ToResponseList(rolePermissions));
    }

    public async Task<Result<List<RolePermissionResponse>>> GetRolesByPermissionAsync(Guid permissionId, CancellationToken ct = default)
    {
        var permission = await permissionStore.GetByIdAsync(permissionId, ct);
        if (permission is null)
            return Result<List<RolePermissionResponse>>.Failure(RolePermissionErrors.PermissionNotFound);

        var rolePermissions = await rolePermissionStore.GetActiveByPermissionIdAsync(permissionId, ct);
        return Result<List<RolePermissionResponse>>.Success(mapper.ToResponseList(rolePermissions));
    }
}
