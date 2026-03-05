namespace Domain.Shared;

public sealed record Error(string Code, string Message)
{
    public static readonly Error None = new(string.Empty, string.Empty);

    public static readonly Error NullValue =
        new("common.null_value", "The provided value was null.");
}
