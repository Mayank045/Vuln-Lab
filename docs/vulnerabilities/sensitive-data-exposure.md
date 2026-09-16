# Sensitive Data Exposure

## Lab status

This lab is intentionally vulnerable and must only be run against a local or
explicitly authorized VulnLab instance with synthetic records.

## What is demonstrated?

The vulnerable export route returns complete password documents, including
plaintext passwords, internal MongoDB identifiers, owner information, and
user-controlled metadata. The secure comparison route returns only the fields
needed to display a record list.

Both routes require the local training identity:

```text
X-VulnLab-User: user-a
```

```text
GET /api/lab/vulnerable/export
GET /api/lab/secure/export
```

## Expected comparison

The vulnerable response contains a `password` field and internal fields such
as `_id` and `ownerId`. The secure response contains only:

```json
{
  "records": [
    {
      "id": "demo-id",
      "site": "https://example.local",
      "username": "demo-user"
    }
  ]
}
```

## Remediation

Define response DTOs or MongoDB projections for every endpoint. Return only
the fields required by the current client, never plaintext secrets or internal
database identifiers. Store real passwords using a design appropriate to the
product's threat model, and avoid logging or transmitting them unnecessarily.
