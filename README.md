# API Security Monitor

A Java 21 / Spring Boot 4.1.2 graduation-project prototype that records non-sensitive HTTP request metadata, detects excessive request bursts, and presents the results through a secure local monitoring dashboard.

## Current capabilities

- Fail-open servlet-filter logging to PostgreSQL (`api_request_log`).
- Sliding-window excessive-request detection: 5 requests from one direct client IP in 10 seconds.
- MEDIUM-risk security events with a 30-second duplicate-suppression period (`security_event`).
- Read-only, paginated monitoring endpoints backed by DTOs.
- A local monitoring dashboard protected by form login and an in-memory BCrypt administrator.
- Loopback-only binding at `127.0.0.1:8080`.

Detection records an event but never blocks or rate-limits a request.

## Prerequisites

- Java 21
- PostgreSQL 16
- A PostgreSQL database named `api_security_db`
- PowerShell on Windows for the commands below

The configured database user is `postgres`. Hibernate currently uses `ddl-auto: update`, so the existing project tables are created/updated at application startup. The dashboard milestone itself introduces no schema change.

## Required environment variables

Set these variables only in the terminal session used to start the application:

```powershell
$env:DB_PASSWORD = "<your PostgreSQL password>"
$env:MONITOR_ADMIN_PASSWORD = "<a strong local dashboard password>"
```

The dashboard username defaults to `admin`. It can optionally be changed:

```powershell
$env:MONITOR_ADMIN_USERNAME = "<your local administrator name>"
```

Do not add real values to `application.yaml`, README files, shell scripts, or Git. The application refuses to start when `MONITOR_ADMIN_PASSWORD` is absent or blank.

## Build and run

Run the automated tests:

```powershell
.\mvnw.cmd clean test
```

Start the application:

```powershell
.\mvnw.cmd spring-boot:run
```

The server listens only on `http://127.0.0.1:8080`.

## Sign in and use the dashboard

1. Open `http://127.0.0.1:8080/monitoring` in a local browser.
2. Spring Security redirects to the form-login page.
3. Sign in with `MONITOR_ADMIN_USERNAME` (or `admin`) and the value supplied through `MONITOR_ADMIN_PASSWORD`.
4. Use **Refresh** to reload summary metrics, recent request logs, and security events.

The protected, read-only endpoints used by the page are:

- `GET /api/monitoring/summary`
- `GET /api/monitoring/requests?page=0&size=20`
- `GET /api/monitoring/events?page=0&size=20`

Page sizes are capped at 100. Results are newest-first. The request DTO contains only timestamp, direct client IP, method, URI path, response status, and duration. The security-event DTO omits internal deduplication data. No monitoring write or delete endpoint exists.

## Reproducible advisor demonstration

1. Start PostgreSQL and confirm `api_security_db` is available.
2. Set `DB_PASSWORD` and `MONITOR_ADMIN_PASSWORD`, then start the application with `.\mvnw.cmd spring-boot:run`.
3. Open `http://127.0.0.1:8080/monitoring` and sign in.
4. In a second PowerShell window, generate one normal request:

   ```powershell
   Invoke-RestMethod http://127.0.0.1:8080/api/test
   ```

5. Select **Refresh** and show the successful `GET /api/test` request in the recent-requests table.
6. If this demonstration was just repeated, wait at least 30 seconds for the suppression period. Then generate five requests in well under ten seconds:

   ```powershell
   1..5 | ForEach-Object { Invoke-RestMethod http://127.0.0.1:8080/api/test | Out-Null }
   ```

7. Select **Refresh** again.
8. Verify that the request table contains the five calls and the event table contains an `EXCESSIVE_REQUESTS` event with `MEDIUM` risk and a reason describing the observed count, ten-second window, and threshold of five.

Login, dashboard, and monitoring-API traffic is excluded from request logging so the act of viewing the dashboard does not trigger the excessive-request rule. `/api/test` remains anonymously accessible for local traffic generation and is still logged.

## Data-safety boundary

Request and response bodies, query strings, headers, cookies, credentials, and tokens are not collected. The logging filter uses `request.getRequestURI()` rather than the query string, and the monitoring mapper defensively strips a query component from any legacy path value before returning it. The initial client IP is `request.getRemoteAddr()`; forwarded headers are deliberately not trusted until a known reverse-proxy deployment is configured.

Applications must still avoid placing secrets in URL path segments because a raw URI path can contain such values. Endpoint-pattern normalization is a future improvement.

## Current limitations

- Authentication is a single in-memory local administrator; credentials and sessions are lost on restart. There is no registration, password recovery, role administration, JWT, or OAuth2.
- The application uses HTTP without TLS because it is bound to loopback for the MVP. It must not be exposed directly on a network.
- Counts use the application clock and a rolling 24-hour cutoff. The current summary performs ordinary database count queries and has no caching.
- Detection is rule-based rather than machine-learning-assisted at this milestone.
- IP-only burst detection can produce false positives for NAT users, proxies, monitoring tools, and legitimate bursts. An event means the configured rule was reached, not that an attack was proven.
- A fixed suppression time-bucket key prevents common concurrent duplicate inserts. Two events can still occur close together at a bucket boundary.
- The dashboard offers recent tables and basic paging, but no search, filtering, export, charting, event acknowledgement, or destructive operations.
- Automated tests use mocks and a web MVC slice. They do not connect to the development PostgreSQL database; PostgreSQL behavior remains a separate manual/integration verification step.
