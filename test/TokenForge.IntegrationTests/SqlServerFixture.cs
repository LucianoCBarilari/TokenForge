using Infrastructure.DataAccess;
using Microsoft.EntityFrameworkCore;
using Testcontainers.MsSql;

namespace TokenForge.IntegrationTests;

public  class SqlServerFixture : IAsyncLifetime
{
    private readonly MsSqlContainer container = new MsSqlBuilder("mcr.microsoft.com/mssql/server:2022-latest")
    .WithPassword("YourStrong!Passw0rd")  
    .Build();

    public TokenForgeContext context { get; private set; }
    public async ValueTask DisposeAsync()
    {
        await container.DisposeAsync();
        context?.Dispose();
    }

    public async ValueTask  InitializeAsync()
    {
        await container.StartAsync();
        var connString = container.GetConnectionString();

        var options = new DbContextOptionsBuilder<TokenForgeContext>()
            .UseSqlServer(connString)
            .Options;

        context = new TokenForgeContext(options);
        await context.Database.MigrateAsync();
    }
}
