# TokenForge

JWT auth API built with ASP.NET Core (.NET 10), using Clean Architecture, refresh token rotation, and role-based authorization.

## Quick Start
1. Update `src/Web/appsettings.json` with real values for:
   - `ConnectionStrings`
   - `JwtSettings`
   - `RefreshTokenSecurity:HashKey`
   - `AuthCookie`
2. Run:
   - `dotnet restore`
   - `dotnet run --project src/Web/Web.csproj`
3. Swagger (development): `https://localhost:<port>/swagger`

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

