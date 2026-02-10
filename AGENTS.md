# AGENTS.md

## Project Summary
TokenForge is a .NET 8 Web API showcasing JWT authentication with refresh tokens, role-based access, and lockout protection. It mirrors a production-grade architecture (Presentation, Application, Domain, Infrastructure, Tests) and is intended as a clean public repo.

## Solution Layout
- `TokenForge/` Web API project (`net8.0`)
- `TokenForge.Tests/` test project
- `TokenForge.slnx`

## Architecture Overview
- **Presentation**: controllers + API response model
- **Application**: DTOs + services/use cases + interfaces
- **Domain**: entities + errors + interfaces + Result/Error types
- **Infrastructure**: EF Core context, repositories, and service implementations
- **Tests**: unit tests for core services

## Core Features
- JWT access tokens + refresh tokens
- Login lockout after repeated failures
- Role assignment and user management
- Rate limiting on public endpoints
- CORS configuration via `appsettings`
- Forwarded headers support for reverse proxy

## Main Entry
- `TokenForge/Program.cs` wires DI, JWT auth, controllers, Swagger, rate limiting, CORS, and forwarded headers.

## Configuration
- JWT:
  - `JwtSettings:SecretKey`
  - `JwtSettings:Issuer`
  - `JwtSettings:Audience`
- Connection string:
  - `ConnectionStrings:JWT_Security`
- CORS:
  - `Cors:AllowedOrigins`

## Important Notes
- Public endpoints: `POST /api/auth/login`, `POST /api/auth/tokens/refresh`.
- Rate limiting policies: `login` (5/min) and `refresh` (30/min).
- Cookies are `HttpOnly`, `Secure`, `SameSite=Strict`.

## Migrations
Initial migration is included under `TokenForge/Migrations`.

## Tests
Tests live in `TokenForge.Tests` and are being adapted from the original project.

