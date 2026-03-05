using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
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
        AddWebLogging(builder);
        AddExceptionHandling(builder);
        AddWebSecurity(builder);
        AddWebCors(builder);
        AddWebRateLimiting(builder);
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

    private static void AddWebRateLimiting(IHostApplicationBuilder builder)
    {
        builder.Services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

            options.AddFixedWindowLimiter("login", limiterOptions =>
            {
                limiterOptions.Window = TimeSpan.FromMinutes(1);
                limiterOptions.PermitLimit = 5;
                limiterOptions.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
                limiterOptions.QueueLimit = 0;
            });

            options.AddFixedWindowLimiter("refresh", limiterOptions =>
            {
                limiterOptions.Window = TimeSpan.FromMinutes(1);
                limiterOptions.PermitLimit = 30;
                limiterOptions.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
                limiterOptions.QueueLimit = 0;
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
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
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

            if (builder.Environment.IsDevelopment())
            {
                // Overrides para ver logs detallados de tus capas
                loggerConfiguration
                    .MinimumLevel.Override("Web", LogEventLevel.Debug)
                    .MinimumLevel.Override("Application", LogEventLevel.Debug)
                    .MinimumLevel.Override("Infrastructure", LogEventLevel.Debug)
                    .MinimumLevel.Override("Domain", LogEventLevel.Debug);
            }
        });
    }
}
