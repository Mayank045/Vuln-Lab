# Weak Authentication Controls

## Lab status

This lab is intentionally vulnerable and must only be run against a local or
explicitly authorized VulnLab instance using synthetic credentials.

## Demo account

The isolated training routes use one in-memory demo account:

```text
username: demo-user
password: VulnLab-demo-only
```

These credentials are synthetic and must never be reused outside this local
lab.

## Vulnerable comparison

```text
POST /api/lab/auth/vulnerable/login
```

The vulnerable handler has no rate limiting and compares the submitted
password directly with the demo credential. Repeated invalid requests remain
accepted for processing and return the same authentication error.

## Secure comparison

```text
POST /api/lab/auth/secure/login
```

The secure comparison uses a derived password value, timing-safe comparison,
generic authentication errors, and a local per-IP limit of five attempts per
minute. A successful login clears the attempt counter.

## Remediation

Production authentication should use a dedicated user store, a modern
password-hashing policy with a unique per-user salt, secure session or token
handling, generic failure responses, rate limiting backed by shared storage,
account monitoring, and appropriate MFA for sensitive operations. The
`X-VulnLab-User` header and in-memory tokens used by these labs are training
mechanisms, not production authentication.
