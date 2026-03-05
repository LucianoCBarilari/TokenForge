using Application;
using Infrastructure;
using Microsoft.AspNetCore.HttpOverrides;
using Web;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{
    Log.Information("Starting web application");

    var builder = WebApplication.CreateBuilder(args);
    
    builder.AddWebServices();
    builder.AddInfrastructureServices();
    builder.AddApplicationServices();

    var app = builder.Build();

    app.UseSerilogRequestLogging();

    app.UseForwardedHeaders(new ForwardedHeadersOptions
    {
        ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
    });

    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    app.UseRateLimiter();
    app.UseAuthentication();
    app.UseCors("CorsPolicy");
    app.UseAuthorization();

    app.MapControllers();

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
