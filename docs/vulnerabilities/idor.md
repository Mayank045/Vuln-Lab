# IDOR / Broken Object-Level Authorization

## Lab status

This lab is intentionally vulnerable and must only be run against a local or
explicitly authorized VulnLab instance using synthetic records.

## What is demonstrated?

The vulnerable routes require a synthetic caller identity but do not use it
when looking up or deleting a password record. A caller who knows another
record's client-generated `id` can access or delete that record.

The secure comparison routes include both the record ID and the caller's
`ownerId` in the MongoDB filter.

## Local setup

Create two demo records with different synthetic users:

```text
POST /api/lab/passwords
X-VulnLab-User: user-a
```

Use a different ID and `X-VulnLab-User: user-b` for the second record. The
request body must contain `id`, `site`, `username`, and `password`.

## Vulnerable comparison

Request a record as `user-b` using the ID created by `user-a`:

```text
GET /api/lab/vulnerable/passwords/<user-a-record-id>
X-VulnLab-User: user-b
```

The record is returned because the vulnerable handler filters only by `id`.
The vulnerable delete route has the same ownership flaw:

```text
DELETE /api/lab/vulnerable/passwords/<user-a-record-id>
X-VulnLab-User: user-b
```

## Secure comparison

Use the secure route with the same cross-user request:

```text
GET /api/lab/secure/passwords/<user-a-record-id>
X-VulnLab-User: user-b
```

The response is `404` because the record is owned by `user-a`. The secure
delete route also scopes the delete query to `ownerId`.

## Remediation

In a real application, derive the authenticated user identity from a verified
session or token rather than accepting a training header. Every read, update,
and delete query must enforce resource ownership server-side. Never rely on
the client to hide records or provide a trusted owner ID.
