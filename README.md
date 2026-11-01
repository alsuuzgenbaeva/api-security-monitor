# API Security Monitor

The first milestone records non-sensitive HTTP request metadata in PostgreSQL: request time, direct client IP, HTTP method, URI path, response status, and processing duration.

## Data-safety boundary

Request and response bodies, query strings, headers, cookies, credentials, and tokens are not collected. The logger uses the servlet request URI only. Applications must not place secrets in URL path segments because a raw path can contain such values; future endpoint-pattern normalization can further reduce this risk.

The initial client IP is `request.getRemoteAddr()`. Forwarded headers are deliberately not trusted until a known reverse-proxy deployment is configured.

## Excessive-request detection

After a request log commits, a transaction event checks how many requests the same direct client IP made during a sliding time window. Demonstration defaults are 5 requests in 10 seconds, with a 30-second suppression period and MEDIUM risk. Detection records a security event but never blocks or rate-limits a request.

Cooldown lookup prevents ordinary repeated events. A unique key based on event type, IP, and a fixed suppression time bucket prevents concurrent duplicate inserts. Two events can still occur close together at a time-bucket boundary; removing that edge case would require stronger database locking or a future atomic Redis design.

IP-only rate detection can produce false positives for NAT users, proxies, monitoring tools, and legitimate burst traffic. An event means that the configured rule was exceeded, not that an attack was proven. Security events are intentionally not exposed through an unauthenticated HTTP endpoint.

## Local verification endpoint

`GET /api/test` returns a small JSON status message. `/error` and `/favicon.ico` are excluded from request logging.
