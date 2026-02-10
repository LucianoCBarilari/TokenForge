# TokenForge

Clean, public-ready JWT auth API (ASP.NET Core 8) with refresh tokens, roles, and lockout protection.

## Quick Start
1. Update `TokenForge/appsettings.json` with real `JwtSettings` and connection string.
2. Run:
   - `dotnet restore`
   - `dotnet run --project TokenForge/TokenForge.csproj`
3. Swagger: `http://localhost:5000/swagger` (dev)

## Notes
- Rate limiting is enabled for login + refresh endpoints.
- CORS allows origins from `Cors:AllowedOrigins` in appsettings.
- Behind NGINX, forwarded headers are enabled.

