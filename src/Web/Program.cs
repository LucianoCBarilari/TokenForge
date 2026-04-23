using Application;
using DotNetEnv;
using Infrastructure;
using Infrastructure.DataAccess;
using Infrastructure.DataAccess.Seeds;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using System.Net;
using Web;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{
    Log.Information("Starting web application");

    var builder = WebApplication.CreateBuilder(args);

    // Load .env file if present (local dev without Docker).
    // In production/Docker the variables come from the container environment.
    var envPath = Path.Combine(builder.Environment.ContentRootPath, "..", "..", "..", "..", ".env");
    if (File.Exists(envPath))
    {
        Env.Load(envPath);
        Log.Information(".env file loaded from {Path}", Path.GetFullPath(envPath));
    }
    
    builder.AddWebServices();
    builder.AddInfrastructureServices();
    builder.AddApplicationServices();

    var app = builder.Build();

    using (var scope = app.Services.CreateScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<TokenForgeContext>();
        await db.Database.MigrateAsync();

        var bootstrapSeeder = scope.ServiceProvider.GetRequiredService<BootstrapAdminSeedRunner>();
        await bootstrapSeeder.RunAsync();
    }

    app.UseSerilogRequestLogging();

    app.UseForwardedHeaders(BuildForwardedHeadersOptions(app.Configuration));

    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }
    app.UseExceptionHandler();
    app.UseRateLimiter();
    app.UseAuthentication();
    app.UseCors("CorsPolicy");
    app.UseAuthorization();

    app.MapControllers();
    app.MapHealthChecks("/health", new HealthCheckOptions
    {
        Predicate = healthCheck => healthCheck.Tags.Contains("live")
    });
    app.MapHealthChecks("/health/ready", new HealthCheckOptions
    {
        Predicate = healthCheck => healthCheck.Tags.Contains("ready")
    });

    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Application terminated unexpectedly");
    Console.WriteLine($"FATAL ERROR: {ex.Message}");
    Console.WriteLine(ex.StackTrace);
}
finally
{
    Log.CloseAndFlush();
}

static ForwardedHeadersOptions BuildForwardedHeadersOptions(IConfiguration configuration)
{
    var options = new ForwardedHeadersOptions
    {
        ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
        ForwardLimit = configuration.GetValue<int?>("ForwardedHeaders:ForwardLimit") ?? 1
    };

    var knownProxies = configuration.GetSection("ForwardedHeaders:KnownProxies").Get<string[]>() ?? [];
    foreach (var proxy in knownProxies)
    {
        if (IPAddress.TryParse(proxy, out var ipAddress))
            options.KnownProxies.Add(ipAddress);
    }

    return options;
}
