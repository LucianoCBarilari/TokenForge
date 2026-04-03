using Application.Abstractions.Common;

namespace Infrastructure.Ports.Common;

public class SystemClock : IClock
{
    public DateTime UtcNow => DateTime.UtcNow;
}
