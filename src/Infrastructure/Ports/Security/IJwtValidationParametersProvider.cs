using Microsoft.IdentityModel.Tokens;

namespace Infrastructure.Ports.Security;

public interface IJwtValidationParametersProvider
{
    TokenValidationParameters GetValidationParameters();
}
