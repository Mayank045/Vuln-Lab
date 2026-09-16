# Insecure Input Validation

## Lab status

This lab is intentionally vulnerable and must only be run against a local or
explicitly authorized VulnLab instance with synthetic data.

## Endpoints

Both routes require a local training identity:

```text
X-VulnLab-User: validation-user
```

```text
POST /api/lab/vulnerable/records
POST /api/lab/secure/records
```

## Vulnerable comparison

The vulnerable route checks only that the body is a JSON object. It accepts
arbitrary extra fields, weak values, missing password-manager fields, and
untrusted client data.

## Secure comparison

The secure route uses an explicit allowlist and validates:

- Required string fields
- HTTPS or HTTP site URLs
- Length limits for IDs, sites, usernames, passwords, and notes
- Optional notes type
- No unexpected fields

The owner identity is added by the server instead of trusted from the body.

## Remediation

Perform validation on the server even when the frontend validates input.
Reject unexpected fields, enforce type and length constraints, validate values
according to their intended format, and construct persisted documents from
approved fields rather than spreading the complete request body.
