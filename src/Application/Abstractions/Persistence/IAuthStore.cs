namespace Application.Abstractions.Persistence;

public interface IAuthStore
{
    Task<LoginAttempt?> GetLoginAttemptAsync(string userAccount, CancellationToken ct = default);
    Task AddLoginAttemptAsync(LoginAttempt attempt, CancellationToken ct = default);
    void UpdateLoginAttempt(LoginAttempt attempt);

    Task<RefreshToken?> GetValidRefreshTokenAsync(
        string token,
        DateTime nowUtc,
        CancellationToken ct = default);

    Task<List<RefreshToken>> GetActiveRefreshTokensAsync(
        Guid userId,
        DateTime nowUtc,
        CancellationToken ct = default);

    Task<RefreshToken?> GetActiveRefreshTokenByValueAsync(
        Guid userId,
        string token,
        CancellationToken ct = default);

    Task AddRefreshTokenAsync(RefreshToken token, CancellationToken ct = default);
    void UpdateRefreshToken(RefreshToken token);
    void UpdateRefreshTokens(IEnumerable<RefreshToken> tokens);
    Task SaveChangesAsync(CancellationToken ct = default);
}
