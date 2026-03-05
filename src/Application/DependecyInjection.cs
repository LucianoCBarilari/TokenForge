using Application.Common;
using Application.Feature.AuthFeature;
using Application.Feature.LockoutFeature;
using Application.Feature.RefreshTokenFeature;
using Application.Feature.RoleFeature;
using Application.Feature.TokenFeature;
using Application.Feature.UserFeature;
using Application.Feature.UserRoleFeature;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Application;

public static class DependecyInjection
{
    public static void AddApplicationServices(this IHostApplicationBuilder builder)
    {
        builder.Services.AddScoped<IAuthService, AuthService>();
        builder.Services.AddScoped<ILockoutService, LockoutService>();
        builder.Services.AddScoped<IHandleRefreshToken, HandleRefreshToken>();
        builder.Services.AddScoped<ITokenService, TokenService>();
        builder.Services.AddScoped<IUserService, UserService>();
        builder.Services.AddScoped<IUserRoleService, UserRoleService>();
        builder.Services.AddScoped<IRoleService, RoleService>();

        builder.Services.AddSingleton<Helpers>();

        builder.Services.AddSingleton<RoleMapper>();
        builder.Services.AddSingleton<UserMapper>();
        builder.Services.AddSingleton<UserRoleMapper>();
    }
}
