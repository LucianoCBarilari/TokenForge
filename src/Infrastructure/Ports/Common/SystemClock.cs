using Application.Abstractions.Common;

namespace Infrastructure.Ports.Common;

public sealed class SystemClock : IClock
{
    public DateTime UtcNow => DateTime.UtcNow;
}
