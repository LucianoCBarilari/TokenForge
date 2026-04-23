using Application.Constants;
using Infrastructure.DataAccess;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi;
using Serilog;
using Serilog.Events;
using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
using Web.Security;

namespace Web;

public static class DependencyInjection
{
    public static void AddWebServices(this IHostApplicationBuilder builder)
    {
        ValidateWebConfiguration(builder);
        AddWebLogging(builder);
        AddExceptionHandling(builder);
        AddWebSecurity(builder);
        AddWebCors(builder);
        AddWebRateLimiting(builder);
        AddWebHealthChecks(builder);
        AddWebSwagger(builder);
        builder.Services.AddScoped<AuthCookieWriter>();

        builder.Services.AddControllers()
         .AddJsonOptions(options =>
         {

             options.JsonSerializerOptions.PropertyNameCaseInsensitive = true;
             options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
             options.JsonSerializerOptions.WriteIndented = builder.Environment.IsDevelopment();
         });
    }
    private static void AddWebHealthChecks(IHostApplicationBuilder builder)
    {
        builder.Services
            .AddHealthChecks()
            .AddCheck("self", () => HealthCheckResult.Healthy(), tags: ["live"])
            .AddCheck<DatabaseHealthCheck>("database", tags: ["ready"]);
    }
    private static void AddWebRateLimiting(IHostApplicationBuilder builder)
    {
        builder.Services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

            options.AddPolicy("login", httpContext =>
            {
                var ip = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

                return RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: $"login:{ip}",
                    factory: _ => new FixedWindowRateLimiterOptions
                    {
                        Window = TimeSpan.FromMinutes(1),
                        PermitLimit = 10,
                        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                        QueueLimit = 0
                    });
            });

            options.AddPolicy("refresh", httpContext =>
            {
                var ip = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

                return RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: $"refresh:{ip}",
                    factory: _ => new FixedWindowRateLimiterOptions
                    {
                        Window = TimeSpan.FromMinutes(1),
                        PermitLimit = 30,
                        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                        QueueLimit = 0
                    });
            });
        });
    }
    private static void AddWebCors(IHostApplicationBuilder builder)
    {
        var corsOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? Array.Empty<string>();
        builder.Services.AddCors(options =>
        {
            options.AddPolicy("CorsPolicy", policy =>
            {
                if (corsOrigins.Length > 0)
                {
                    policy.WithOrigins(corsOrigins)
                        .AllowAnyHeader()
                        .AllowAnyMethod()
                        .AllowCredentials();
                }
            });
        });
    }
    private static void AddWebSwagger(IHostApplicationBuilder builder)
    {
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen(options =>
        {
            options.SwaggerDoc("v1", new OpenApiInfo
            {
                Title = "TokenForge API",
                Version = "v1"
            });

            options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                Name = "Authorization",
                In = ParameterLocation.Header,
                Type = SecuritySchemeType.Http,
                Scheme = "bearer",
                BearerFormat = "JWT",
                Description = "Ingrese el token JWT así: Bearer {token}"
            });

            options.AddSecurityRequirement(document =>
            {
                return new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecuritySchemeReference("Bearer"),
                        new List<string>()
                    }
                };
            });
        });
    }
    private static void AddWebSecurity(IHostApplicationBuilder builder)
    {
        builder.Services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 },
                ValidIssuer = builder.Configuration["JwtSettings:Issuer"],
                ValidAudience = builder.Configuration["JwtSettings:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(builder.Configuration["JwtSettings:SecretKey"]
                    ?? throw new InvalidOperationException("SecretKey not found.")))
            };
            options.Events = new JwtBearerEvents
            {
                OnMessageReceived = context =>
                {
                    if (string.IsNullOrEmpty(context.Token))
                    {
                        var accessToken = context.Request.Cookies["accessToken"];
                        if (!string.IsNullOrWhiteSpace(accessToken))
                        {
                            context.Token = accessToken;
                        }
                    }
                    return Task.CompletedTask;
                }
            };
        });

        builder.Services.AddAuthorization(options =>
        {            

            foreach (var permission in PermissionCodes.GetAll())
            {
                options.AddPolicy(permission, policy =>
                    policy.RequireClaim(CustomClaimTypes.Permission, permission));
            }
        });

    }
    private static void AddExceptionHandling(IHostApplicationBuilder builder)
    {
        //ProblemDetails (RFC 7807/9457)
        builder.Services.AddProblemDetails(options =>
        {

            options.CustomizeProblemDetails = ctx =>
            {
                var problem = ctx.ProblemDetails;

                problem.Instance = $"{ctx.HttpContext.Request.Method} {ctx.HttpContext.Request.Path}";
                problem.Extensions["traceId"] = ctx.HttpContext.TraceIdentifier;
                problem.Extensions["timestamp"] = DateTime.UtcNow.ToString("o");  // ISO 8601


                if (!ctx.HttpContext.RequestServices.GetRequiredService<IHostEnvironment>().IsDevelopment())
                {
                    problem.Detail = null;
                }
            };
        });
        builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
    }
    private static void AddWebLogging(IHostApplicationBuilder builder)
    {
        var logsDirectory = Path.Combine(Directory.GetCurrentDirectory(), "logs");
        Directory.CreateDirectory(logsDirectory);

        builder.Logging.ClearProviders();
        builder.Services.AddSerilog((services, loggerConfiguration) =>
        {
            loggerConfiguration
                .ReadFrom.Configuration(builder.Configuration)
                .ReadFrom.Services(services)
                .Enrich.FromLogContext()
                .Enrich.WithProperty("Application", "TokenForge.Web")
                .Enrich.WithProperty("Environment", builder.Environment.EnvironmentName);

            // Si no hay configuración en appsettings, configuramos valores por defecto
            if (!builder.Configuration.GetSection("Serilog").Exists())
            {
                loggerConfiguration
                    .MinimumLevel.Information()
                    .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
                    .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
                    .WriteTo.Console()
                    .WriteTo.File(
                        Path.Combine(logsDirectory, "web-.log"),
                        rollingInterval: RollingInterval.Day,
                        retainedFileCountLimit: 14);
            }

            if (!builder.Environment.IsDevelopment())
            {
                loggerConfiguration.WriteTo.File(
                    Path.Combine(logsDirectory, "web-.log"),
                    rollingInterval: RollingInterval.Day,
                    retainedFileCountLimit: 30,
                    outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss} {Level:u3}] {Message:lj} {Properties:j}{NewLine}{Exception}");
            }

            if (builder.Environment.IsDevelopment())
            {
                loggerConfiguration
                    .MinimumLevel.Override("Web", LogEventLevel.Debug)
                    .MinimumLevel.Override("Application", LogEventLevel.Debug)
                    .MinimumLevel.Override("Infrastructure", LogEventLevel.Debug)
                    .MinimumLevel.Override("Domain", LogEventLevel.Debug);
            }
        });
    }
    private static void ValidateWebConfiguration(IHostApplicationBuilder builder)
    {
        var configuration = builder.Configuration;
        var environment = builder.Environment;

        var jwtSecret = configuration["JwtSettings:SecretKey"];
        var refreshHashKey = configuration["RefreshTokenSecurity:HashKey"];
        var connectionString = configuration.GetConnectionString("JWT_Security");

        ValidateRequiredValue(jwtSecret, "JwtSettings:SecretKey");
        ValidateRequiredValue(refreshHashKey, "RefreshTokenSecurity:HashKey");
        ValidateRequiredValue(connectionString, "ConnectionStrings:JWT_Security");

        if (environment.IsProduction())
        {
            ValidateNotPlaceholder(jwtSecret, "JwtSettings:SecretKey");
            ValidateNotPlaceholder(refreshHashKey, "RefreshTokenSecurity:HashKey");

            ValidateMinimumLength(jwtSecret!, "JwtSettings:SecretKey", 32);
            ValidateMinimumLength(refreshHashKey!, "RefreshTokenSecurity:HashKey", 32);
        }

        var bootstrapAdminEnabled = configuration.GetValue<bool>("BootstrapAdmin:Enabled");
        if (bootstrapAdminEnabled)
        {
            var adminUserAccount = configuration["BootstrapAdmin:UserAccount"];
            var adminEmail = configuration["BootstrapAdmin:Email"];
            var adminPassword = configuration["BootstrapAdmin:Password"];
            var adminRoleName = configuration["BootstrapAdmin:RoleName"];

            ValidateRequiredValue(adminUserAccount, "BootstrapAdmin:UserAccount");
            ValidateRequiredValue(adminEmail, "BootstrapAdmin:Email");
            ValidateRequiredValue(adminPassword, "BootstrapAdmin:Password");
            ValidateRequiredValue(adminRoleName, "BootstrapAdmin:RoleName");

            if (environment.IsProduction())
            {
                ValidateNotPlaceholder(adminPassword, "BootstrapAdmin:Password");
                ValidateMinimumLength(adminPassword!, "BootstrapAdmin:Password", 12);

                Log.Warning(
                    "*** SECURITY WARNING: BootstrapAdmin is ENABLED in Production. " +
                    "Set BootstrapAdmin:Enabled=false immediately after the first login. ***");
            }
        }
    }
    private static void ValidateRequiredValue(string? value, string key)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new InvalidOperationException($"Configuration value '{key}' is required.");
    }
    private static void ValidateNotPlaceholder(string? value, string key)
    {
        if (string.Equals(value?.Trim(), "CHANGE_ME", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Configuration value '{key}' must be replaced before running in Production.");
    }
    private static void ValidateMinimumLength(string value, string key, int minLength)
    {
        if (value.Trim().Length < minLength)
            throw new InvalidOperationException($"Configuration value '{key}' must be at least {minLength} characters long.");
    }

}
