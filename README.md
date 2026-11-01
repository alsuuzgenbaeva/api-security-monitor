# API Security Monitor

The first milestone records non-sensitive HTTP request metadata in PostgreSQL: request time, direct client IP, HTTP method, URI path, response status, and processing duration.

## Data-safety boundary

Request and response bodies, query strings, headers, cookies, credentials, and tokens are not collected. The logger uses the servlet request URI only. Applications must not place secrets in URL path segments because a raw path can contain such values; future endpoint-pattern normalization can further reduce this risk.

The initial client IP is `request.getRemoteAddr()`. Forwarded headers are deliberately not trusted until a known reverse-proxy deployment is configured.

## Local verification endpoint

`GET /api/test` returns a small JSON status message. `/error` and `/favicon.ico` are excluded from request logging.
