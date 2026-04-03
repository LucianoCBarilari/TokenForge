using Microsoft.IdentityModel.Tokens;

namespace Infrastructure.Security;

public interface IJwtValidationParametersProvider
{
    TokenValidationParameters GetValidationParameters();
}
