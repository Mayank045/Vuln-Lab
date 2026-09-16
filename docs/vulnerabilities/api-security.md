# API Security Review

## Lab status

This lab is intentionally vulnerable and must only be run against a local or
explicitly authorized VulnLab instance with synthetic records.

## API coverage

The existing root API remains available for the original password-manager UI:

| Method | Route | Current behavior |
|---|---|---|
| GET | `/` | Returns all password documents |
| POST | `/` | Inserts the complete request body |
| DELETE | `/` | Deletes using the complete request body |

The isolated lab routes cover ownership, query construction, data exposure,
authentication, validation, headers, and object mutation.

## Mutation comparison

```text
PUT /api/lab/vulnerable/passwords/:id
PATCH /api/lab/secure/passwords/:id
```

The vulnerable update accepts arbitrary fields and updates any known record ID
without checking ownership. The secure update requires the synthetic caller's
`ownerId`, accepts only approved string fields, and rejects unexpected or
non-string values.

## API remediation checklist

- Authenticate every protected route.
- Enforce ownership or role authorization on every object operation.
- Validate path parameters and request bodies server-side.
- Allowlist writable fields and construct update documents explicitly.
- Project response fields to the minimum required by the client.
- Apply request size limits, rate limits, and secure headers.
- Use consistent status codes and non-sensitive error messages.
- Add automated tests for unauthenticated, cross-user, invalid-input, and
  excessive-data cases.

The training identity header is not production authentication. A deployed
version must derive identity from a verified session or token.
