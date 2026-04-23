# TokenForge

JWT authentication API built with ASP.NET Core (.NET 10), using Clean Architecture, HttpOnly cookie delivery, refresh token rotation, reuse detection, and role-based authorization with granular permissions.

---

## Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
  - [Option A: Docker](#option-a-docker)
  - [Option B: Local (.NET CLI)](#option-b-local-net-cli)
- [Environment Variables](#environment-variables)
- [Default Roles and Permissions](#default-roles-and-permissions)
  - [Customizing Before First Start](#customizing-before-first-start)
- [Bootstrap Admin Account](#bootstrap-admin-account)
- [Authorization Model](#authorization-model)
- [Auth and Token Security](#auth-and-token-security)
- [API Endpoints](#api-endpoints)
- [Pre-deployment Checklist](#pre-deployment-checklist)
- [Operational Notes](#operational-notes)
- [Standards and References](#standards-and-references)

---

## Features

- JWT access tokens delivered via `HttpOnly` cookies (not exposed to JavaScript)
- Refresh token rotation on every use
- Reuse detection: a reused revoked token triggers full session revocation for that user
- Refresh tokens stored hashed (HMAC-SHA256), never plaintext
- Granular permission claims embedded in the JWT
- Role and permission management via API
- Account lockout after failed login attempts
- Bootstrap admin account on startup (configurable)
- Rate limiting on login and refresh endpoints
- Health check endpoints (`/health`, `/health/ready`)
- ProblemDetails (RFC 7807) error responses

---

## Tech Stack

- **Runtime**: .NET 10, ASP.NET Core
- **ORM**: Entity Framework Core (SQL Server)
- **Architecture**: Clean Architecture (Domain / Application / Infrastructure / Web)
- **Auth**: JWT Bearer + HttpOnly cookie transport
- **Logging**: Serilog

---

## Getting Started

### Option A: Docker

> Requires Docker and an existing SQL Server instance accessible from the container.

1. Copy `.env.example` to `.env` and fill in all values:

   ```bash
   cp .env.example .env
   ```

2. Start the container:

   ```bash
   docker compose up -d
   ```

   The API starts on port `8080`. All environment variables are loaded from `.env` via `env_file` in `docker-compose.yml`. On first boot, EF Core migrations run automatically and seed data is applied.

3. If `BootstrapAdmin__Enabled=true` in your `.env`, the admin account is created on startup. **Disable it after the first login.**

---

### Option B: Local (.NET CLI)

1. Copy `.env.example` to `.env` and fill in all values:

   ```bash
   cp .env.example .env
   ```

   The app automatically loads `.env` when running locally (via DotNetEnv). No manual export needed.

2. Restore and run:

   ```bash
   dotnet restore
   dotnet run --project src/Web/Web.csproj
   ```

3. Swagger UI (development only): `https://localhost:<port>/swagger`

---

## Environment Variables

All sensitive configuration lives in `.env` (never committed). Use `.env.example` as the template.

| Variable | Description |
|---|---|
| `JwtSettings__SecretKey` | Secret key for signing JWT tokens (min 32 chars in production) |
| `JwtSettings__Issuer` | Token issuer claim |
| `JwtSettings__Audience` | Token audience claim |
| `JwtSettings__ExpirationMinutes` | Access token lifetime in minutes |
| `RefreshTokenSecurity__HashKey` | HMAC key for hashing refresh tokens (min 32 chars in production) |
| `RefreshTokenSecurity__ExpirationDays` | Refresh token lifetime in days |
| `ConnectionStrings__JWT_Security` | SQL Server connection string |
| `AuthCookie__AccessTokenName` | Cookie name for the access token |
| `AuthCookie__RefreshTokenName` | Cookie name for the refresh token |
| `AuthCookie__Secure` | `true` to enforce HTTPS-only cookies |
| `AuthCookie__SameSite` | `Strict`, `Lax`, or `None` |
| `Cors__AllowedOrigins__0` | First allowed CORS origin (repeat with `__1`, `__2`, ...) |
| `BootstrapAdmin__Enabled` | `true` to create the admin account on startup |
| `BootstrapAdmin__UserAccount` | Admin username |
| `BootstrapAdmin__Email` | Admin email |
| `BootstrapAdmin__Password` | Admin password (min 12 chars in production) |
| `BootstrapAdmin__RoleName` | Role to assign to the bootstrap admin (e.g. `Admin`) |

> Use double underscores (`__`) as the section separator in variable names. ASP.NET Core maps them to nested configuration sections automatically.

---

## Default Roles and Permissions

TokenForge ships with three pre-defined roles and a full permission catalog applied via EF Core seed data. The database is seeded automatically on first start.

### Roles

| Role | Description |
|---|---|
| **Admin** | Full access — all permissions |
| **Manager** | Operational access — user and role management, no global token revocation, no permission management |
| **User** | Self-service only — login, logout, refresh, revoke own session |

### Permission Catalog

| Permission Code | Description |
|---|---|
| `auth.login` | Authenticate and start a session |
| `auth.logout` | Close the current session |
| `tokens.refresh` | Refresh an access token |
| `tokens.revoke.current` | Revoke own current refresh token |
| `tokens.revoke.all` | Revoke all refresh tokens for any user (Admin only) |
| `users.read` | Read user information |
| `users.write` | Create or update users |
| `users.create` | Create new users |
| `users.update.email` | Update a user's email |
| `users.update.account` | Update a user's account name |
| `users.update.password` | Update a user's password |
| `users.disable` | Disable user accounts |
| `users.read.roles` | Read roles assigned to a user |
| `roles.read` | Read role information |
| `roles.write` | Create roles |
| `roles.update` | Update role information |
| `roles.read.users` | Read users assigned to a role |
| `permissions.read` | Read permission information |
| `permissions.create` | Create new permissions |
| `permissions.update` | Update existing permissions |
| `permissions.activate` | Reactivate permissions |
| `permissions.deactivate` | Deactivate permissions |
| `rolepermissions.assign` | Assign permissions to a role |
| `rolepermissions.revoke` | Revoke permissions from a role |
| `rolepermissions.sync` | Sync permission assignments for a role |
| `rolepermissions.read` | Read role-permission assignments |
| `userroles.assign` | Assign roles to a user |
| `userroles.revoke` | Revoke role assignments from a user |
| `userroles.read` | Read user-role assignments |

### Customizing Before First Start

To change the default roles, permissions, or role-permission assignments before the first deployment:

1. Edit the seed files in `src/Infrastructure/DataAccess/Seeds/`:
   - `RoleSeed.cs` — add, rename, or remove roles
   - `PermissionSeed.cs` — add, rename, or remove permissions
   - `RolePermissionSeed.cs` — adjust which permissions each role gets
2. Create a new migration to capture the changes:

   ```bash
   $env:ASPNETCORE_ENVIRONMENT="Development"
   dotnet ef migrations add UpdateSeeds --project src/Infrastructure --startup-project src/Web
   ```

3. Start the app — `MigrateAsync()` applies the migration and seeds data automatically.

> If you only need to adjust roles and permissions after the system is running, use the API endpoints directly — no migration needed.

---

## Bootstrap Admin Account

When `BootstrapAdmin__Enabled=true`, the app creates an admin user on startup if it does not already exist. This is intended for the very first deployment only.

**Recommended flow:**

1. Set `BootstrapAdmin__Enabled=true` with the desired credentials in `.env`
2. Start the app — the account is created automatically
3. Log in, change the password via the API
4. Set `BootstrapAdmin__Enabled=false` and restart

> In production, a warning is logged at startup if Bootstrap is still enabled. Do not leave it on.

---

## Authorization Model

- **Roles** are high-level access groups: `Admin`, `Manager`, `User`
- **Permissions** are granular claims embedded in the JWT
- The access token carries the full permission list for the authenticated user's roles
- Endpoints are protected by policy, not by role — e.g. `[Authorize(Policy = "users.create")]`
- Keep permission codes stable even if routes change — use domain capability names like `users.update.email` instead of route names
- For frontend authorization, derive simple UI capabilities from permissions rather than checking every code in every component

---

## Auth and Token Security

- Access token and refresh token delivered as `HttpOnly` cookies
- Refresh token cookie path is restricted to `/api/auth/tokens` — the browser only sends it to that path
- Refresh tokens stored as HMAC-SHA256 hashes, never plaintext
- Refresh endpoint rotates the refresh token on each use
- Reuse detection: if a revoked token is submitted, all active sessions for that user are revoked immediately
- Account lockout triggers after 3 consecutive failed login attempts

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/auth/login` | Authenticate and receive cookies |
| `POST` | `/api/auth/logout` | Revoke current session and clear cookies |
| `POST` | `/api/auth/tokens` | Refresh the access token |
| `POST` | `/api/auth/tokens/revoke/current` | Revoke current refresh token |
| `POST` | `/api/auth/tokens/revoke/users/{userId}` | Revoke all tokens for a user (Admin) |

> Full endpoint documentation is available at `/swagger` when running in Development mode.

---

## Pre-deployment Checklist

- [ ] Replace all `CHANGE_ME` placeholders in `.env`
- [ ] `JwtSettings__SecretKey` and `RefreshTokenSecurity__HashKey` are at least 32 characters
- [ ] `ConnectionStrings__JWT_Security` points to your SQL Server instance
- [ ] `Cors__AllowedOrigins` lists only your intended frontend domains
- [ ] `AuthCookie__Secure=true` for HTTPS environments
- [ ] `ASPNETCORE_ENVIRONMENT=Production` is set in the container or host
- [ ] `BootstrapAdmin__Enabled=false` after the first admin login
- [ ] Nginx (or your reverse proxy) is configured with security headers and SSL termination
- [ ] `ForwardedHeaders` is configured if the API runs behind a proxy or load balancer
- [ ] `/health` and `/health/ready` are reachable from your deployment health checker
- [ ] Rate limit values match your expected traffic

---

## Operational Notes

- Rate limiting is enabled for the login endpoint (10 req/min per IP) and the refresh endpoint (30 req/min per IP)
- CORS uses `Cors__AllowedOrigins` from configuration — no wildcards in production
- Error responses follow ProblemDetails (RFC 7807/9457) format
- Swagger is only available in Development mode by default
- Logs are written to `logs/` with daily rolling files

---

## Standards and References

Refresh-token design follows:

- [RFC 6749 §1.5](https://datatracker.ietf.org/doc/html/rfc6749#section-1.5) — Refresh token concept
- [RFC 6819 §5.1.4.2.2](https://datatracker.ietf.org/doc/html/rfc6819#section-5.1.4.2.2) — High-entropy token generation
- [RFC 6819 §5.2.2.3](https://datatracker.ietf.org/doc/html/rfc6819#section-5.2.2.3) — Refresh token rotation
- [RFC 6819 §5.2.2.4](https://datatracker.ietf.org/doc/html/rfc6819#section-5.2.2.4) — Token revocation
- [RFC 6819 §5.1.4.1.3](https://datatracker.ietf.org/doc/html/rfc6819#section-5.1.4.1.3) — Avoid storing token material in cleartext
