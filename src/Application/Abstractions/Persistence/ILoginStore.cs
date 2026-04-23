using Application.Feature.AuthFeature.AuthDto;

namespace Application.Abstractions.Persistence;

public interface ILoginStore
{
    Task<UserWithLastAttemptDto?> GetUserWithLastLoginAsync(string userAccount);
    Task<UserRolesPermissionsDto> GetUserRolesAndPermissionsAsync(Guid userId, CancellationToken ct = default);
}
