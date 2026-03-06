using Application.Abstractions.Common;

namespace Application.Feature.PermissionFeature;

public class PermissionService(
    IPermissionStore permissionStore,
    IClock clock,
    PermissionMapper mapper) : IPermissionService
{
    public async Task<Result<PermissionResponse>> CreatePermissionAsync(PermissionCreateInputDto input, CancellationToken ct = default)
    {
        var code = input.PermissionCode.Trim();
        if (string.IsNullOrWhiteSpace(code))
            return Result<PermissionResponse>.Failure(PermissionErrors.InvalidPermissionCode);

        var existing = await permissionStore.GetByCodeAsync(code, ct);
        if (existing is not null)
            return Result<PermissionResponse>.Failure(PermissionErrors.PermissionAlreadyExists);

        var permission = mapper.ToEntity(input);
        permission.PermissionId = Guid.NewGuid();
        permission.PermissionCode = code;
        permission.PermissionName = input.PermissionName.Trim();
        permission.PermissionDescription = input.PermissionDescription?.Trim();
        permission.IsActive = true;
        permission.CreatedAt = clock.UtcNow;

        await permissionStore.AddAsync(permission, ct);
        await permissionStore.SaveChangesAsync(ct);
        return Result<PermissionResponse>.Success(mapper.ToResponse(permission));
    }

    public async Task<Result> UpdatePermissionAsync(PermissionUpdateInputDto input, CancellationToken ct = default)
    {
        var permission = await permissionStore.GetByIdAsync(input.PermissionId, ct);
        if (permission is null)
            return Result.Failure(PermissionErrors.PermissionNotFound);

        mapper.ApplyUpdate(input, permission);
        if (!string.IsNullOrWhiteSpace(input.PermissionName))
            permission.PermissionName = input.PermissionName.Trim();
        permission.PermissionDescription = input.PermissionDescription?.Trim();

        permissionStore.Update(permission);
        await permissionStore.SaveChangesAsync(ct);
        return Result.Success();
    }

    public async Task<Result> DeactivatePermissionAsync(Guid permissionId, CancellationToken ct = default)
    {
        var permission = await permissionStore.GetByIdAsync(permissionId, ct);
        if (permission is null)
            return Result.Failure(PermissionErrors.PermissionNotFound);

        permission.IsActive = false;
        permission.RevokedAt = clock.UtcNow;
        permissionStore.Update(permission);
        await permissionStore.SaveChangesAsync(ct);
        return Result.Success();
    }

    public async Task<Result> ReactivatePermissionAsync(Guid permissionId, CancellationToken ct = default)
    {
        var permission = await permissionStore.GetByIdAsync(permissionId, ct);
        if (permission is null)
            return Result.Failure(PermissionErrors.PermissionNotFound);

        permission.IsActive = true;
        permission.RevokedAt = null;
        permissionStore.Update(permission);
        await permissionStore.SaveChangesAsync(ct);
        return Result.Success();
    }

    public async Task<Result<PermissionResponse>> GetPermissionByIdAsync(Guid permissionId, CancellationToken ct = default)
    {
        var permission = await permissionStore.GetByIdAsync(permissionId, ct);
        if (permission is null)
            return Result<PermissionResponse>.Failure(PermissionErrors.PermissionNotFound);

        return Result<PermissionResponse>.Success(mapper.ToResponse(permission));
    }

    public async Task<Result<PermissionResponse>> GetPermissionByCodeAsync(string permissionCode, CancellationToken ct = default)
    {
        var permission = await permissionStore.GetByCodeAsync(permissionCode.Trim(), ct);
        if (permission is null)
            return Result<PermissionResponse>.Failure(PermissionErrors.PermissionNotFound);

        return Result<PermissionResponse>.Success(mapper.ToResponse(permission));
    }

    public async Task<Result<List<PermissionResponse>>> GetAllPermissionsAsync(CancellationToken ct = default)
    {
        var permissions = await permissionStore.GetAllAsync(ct);
        return Result<List<PermissionResponse>>.Success(mapper.ToResponseList(permissions));
    }

    public async Task<Result<List<PermissionResponse>>> GetActivePermissionsAsync(CancellationToken ct = default)
    {
        var permissions = await permissionStore.GetActiveAsync(ct);
        return Result<List<PermissionResponse>>.Success(mapper.ToResponseList(permissions));
    }
}
