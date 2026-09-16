# Reflected Cross-Site Scripting

## Lab status

This lab is intentionally vulnerable and must only be run against a local or
explicitly authorized VulnLab instance using synthetic data.

## What is demonstrated?

When the application is opened with a `q` query parameter, the value is shown
in a training panel. The vulnerable preview inserts the value with
`dangerouslySetInnerHTML`. The secure preview renders the same value as a
normal React string, which applies output encoding.

## Testing

Open the local frontend with a harmless HTML value in the `q` query parameter
and compare the vulnerable and secure previews. Keep all testing local and
authorized.

## Remediation

Never insert query-string values into HTML. Render untrusted values as text,
use context-appropriate output encoding, and add a restrictive Content
Security Policy as defense in depth.
