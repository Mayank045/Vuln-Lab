# Security Headers and Information Disclosure

## Lab status

This lab is intentionally vulnerable and must only be run against a local or
explicitly authorized VulnLab instance.

## Header comparison

The vulnerable lab routes retain selected Express defaults and do not add the
recommended browser protection headers. The secure comparison routes under
`/api/lab/secure` remove the Express `X-Powered-By` disclosure and add:

- `Content-Security-Policy`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`
- `Permissions-Policy`

The lab does not set HSTS on localhost because HSTS is intended for a
properly deployed HTTPS origin.

## Information disclosure comparison

```text
GET /api/lab/vulnerable/diagnostics
GET /api/lab/secure/diagnostics
```

The vulnerable response exposes the Node.js version, platform, database name,
environment, server implementation, and route structure. The secure response
returns only a stable service health result.

## Remediation

Set security headers centrally using a reviewed policy, remove framework
fingerprinting, avoid returning runtime and infrastructure details, and keep
detailed diagnostics in protected server-side logs rather than API responses.
Review CSP directives for the actual deployed frontend before enabling a
production policy.
