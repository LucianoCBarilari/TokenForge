namespace Application.Feature.UserFeature;

public enum UserStoreConflictType
{
    Email,
    UserAccount
}

public sealed class UserStoreConflictException(UserStoreConflictType conflictType, Exception innerException)
    : Exception($"User store conflict detected for '{conflictType}'.", innerException)
{
    public UserStoreConflictType ConflictType { get; } = conflictType;
}
