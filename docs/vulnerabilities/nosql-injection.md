# NoSQL Injection

## Lab status

This lab is intentionally vulnerable and must only be run against a local or
explicitly authorized VulnLab instance with synthetic records.

## What is demonstrated?

The vulnerable search endpoint accepts a caller-controlled MongoDB filter
object. It merges that object after the synthetic user's ownership filter,
which allows query operators or an `ownerId` override to change the intended
query.

The secure comparison endpoint accepts only a string site search, escapes
regular-expression characters, applies ownership after input parsing, and
returns a minimum set of fields.

## Endpoints

Both endpoints require the local training header:

```text
X-VulnLab-User: user-a
```

```text
POST /api/lab/vulnerable/search
POST /api/lab/secure/search
```

The vulnerable route expects a JSON filter object. The secure route accepts:

```json
{
  "site": "example"
}
```

## Remediation

Never pass arbitrary request-body objects into MongoDB filters. Validate the
request body against an allowlist of fields and primitive types, reject arrays
and unexpected keys, and construct the database query on the server. Keep
authorization predicates outside caller-controlled input and use projections
to avoid returning unnecessary fields.

The `X-VulnLab-User` header is only a local training identity. Production code
must derive the owner from a verified session or token.
