# TokenForge

JWT auth API built with ASP.NET Core (.NET 10), using Clean Architecture, refresh token rotation, and role-based authorization.

## Quick Start
1. Update `src/Web/appsettings.json` with real values for:
   - `ConnectionStrings`
   - `JwtSettings`
   - `RefreshTokenSecurity:HashKey`
   - `AuthCookie`
2. Configure roles and permissions in `src/Infrastructure/DataAccess/Seeds` if you need to customize the authorization model.
3. Create and apply a new migration after changing seeded roles or permissions.
4. If you want to bootstrap an administrator account on startup, configure `BootstrapAdmin` in `src/Web/appsettings.json`, set `Enabled` to `true`, and provide the desired admin values and role.
5. Run:
   - `dotnet restore`
   - `dotnet run --project src/Web/Web.csproj`
6. Swagger (development): `https://localhost:<port>/swagger`

## Required Setup Checklist
Before considering the API ready to run correctly in a real environment, make sure the following items are completed:

- Replace placeholder secrets such as `JwtSettings:SecretKey` and `RefreshTokenSecurity:HashKey`.
- Set a valid `ConnectionStrings:JWT_Security` value for your SQL Server instance.
- Configure `Cors:AllowedOrigins` for the frontend domains that should be allowed to call the API.
- Review `AuthCookie` settings for your environment, especially `Secure`, `HttpOnly`, `SameSite`, access token lifetime fallback, and refresh token lifetime.
- Review `ForwardedHeaders` configuration if the API will run behind Nginx, a reverse proxy, or a load balancer.
- Keep `ASPNETCORE_ENVIRONMENT=Development` only for local development. Production deployments should run with `Production`.
- If `BootstrapAdmin:Enabled` is set to `true`, provide a real administrator account, password, email, and role name.
- Apply database migrations after changing entity mappings, permission seeds, role seeds, or role-permission seeds.
- Verify that login rate limiting and refresh rate limiting are configured with values that match your expected traffic.
- Decide whether the current single active refresh-token session model per user matches your product requirements.
- Confirm that Swagger remains available only in development unless you intentionally protect and expose it in another environment.
- Verify that `/health` and `/health/ready` are reachable from your deployment environment if you plan to use container or proxy health checks.

## Authorization Model
The API uses both roles and granular permissions.

Rules used in this project:
- Roles are used as high-level access groups: `Admin`, `Manager`, `User`
- Permissions are used as granular claims in JWT tokens
- `Admin` receives the full permission set
- `Manager` receives the operational subset
- `User` receives the minimal self-service subset

## Configuration Notes
- Keep permission codes stable even if routes change.
- Prefer domain capability names like `users.update.email` instead of route names.
- For frontend authorization, derive simple UI capabilities from these permissions instead of checking every permission directly in many components.
- Keep the exact permission catalog, role assignments, and seed values in internal project configuration or source files, not in public documentation.
- For public repositories, document the authorization approach, not the full access matrix.

## Auth and Token Security
- Access token and refresh token are issued as `HttpOnly` cookies.
- Refresh tokens are stored hashed (HMAC-SHA256), not plaintext.
- Refresh endpoint rotates refresh tokens on each successful use.
- Reuse detection is enabled:
  - if a revoked refresh token is reused, all active refresh tokens for that user are revoked.
- Revoke endpoints:
  - `POST /api/auth/tokens/revoke/current` (authenticated user, current session token)
  - `POST /api/auth/tokens/revoke/users/{userId}` (admin, revoke all tokens for target user)

## Standards and References
Refresh-token design in this project follows these references:
- RFC 6749 Section 1.5 (refresh token concept): https://datatracker.ietf.org/doc/html/rfc6749#section-1.5
- RFC 6819 Section 5.1.4.2.2 (high-entropy token generation): https://datatracker.ietf.org/doc/html/rfc6819#section-5.1.4.2.2
- RFC 6819 Section 5.2.2.3 (refresh token rotation): https://datatracker.ietf.org/doc/html/rfc6819#section-5.2.2.3
- RFC 6819 Section 5.2.2.4 (token revocation): https://datatracker.ietf.org/doc/html/rfc6819#section-5.2.2.4
- RFC 6819 Section 5.1.4.1.3 (avoid storing token material in cleartext): https://datatracker.ietf.org/doc/html/rfc6819#section-5.1.4.1.3

## Operational Notes
- Rate limiting is enabled for login and refresh endpoints.
- CORS uses `Cors:AllowedOrigins` from configuration.
- Error responses are returned as `ProblemDetails`.
