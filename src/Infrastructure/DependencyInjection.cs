using Application.Abstractions.Common;
using Application.Abstractions.Persistence;
using Application.Abstractions.Security;
using Infrastructure.DataAccess;
using Infrastructure.DataAccess.Seeds;
using Infrastructure.Ports.Common;
using Infrastructure.Ports.Persistence;
using Infrastructure.Ports.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Infrastructure;

public static class DependencyInjection
{
    public static void AddInfrastructureServices(this IHostApplicationBuilder builder)
    {
        var connectionString = builder.Configuration.GetConnectionString("JWT_Security") ??
            throw new InvalidOperationException("Connection string 'JWT_Security' not found.");

        builder.Services.AddDbContext<TokenForgeContext>(options => options.UseSqlServer(connectionString));
        builder.Services.AddScoped<BootstrapAdminSeedRunner>();
        builder.Services.AddScoped<IUserStore, EfUserStore>();
        builder.Services.AddScoped<IRoleStore, EfRoleStore>();
        builder.Services.AddScoped<IUserRoleStore, EfUserRoleStore>();
        builder.Services.AddScoped<IPermissionStore, EfPermissionStore>();
        builder.Services.AddScoped<IRolePermissionStore, EfRolePermissionStore>();
        builder.Services.AddScoped<IAuthStore, EfAuthStore>();
        builder.Services.AddScoped<IPasswordHasherPort, AspNetPasswordHasherPort>();
        builder.Services.AddScoped<IJwtProvider, JwtProvider>();
        builder.Services.AddSingleton<IJwtValidationParametersProvider, JwtValidationParametersProvider>();
        builder.Services.AddSingleton<IClock, SystemClock>();
    }
}
