# Stored Cross-Site Scripting

## Lab status

This lab is intentionally vulnerable and must only be run against a local or
explicitly authorized VulnLab instance using synthetic data.

## What is demonstrated?

Password records now support a user-controlled `notes` field. The table
intentionally renders that value with `dangerouslySetInnerHTML`, demonstrating
how stored content can become executable markup when output encoding is
skipped. The same value is rendered below using normal React text rendering,
which escapes HTML and provides the secure comparison.

## Testing

Create or edit a local password record and place harmless HTML markup in the
notes field. Reload the page and compare the vulnerable and secure previews.
Do not use this lab against real users, credentials, or external systems.

## Remediation

Prefer framework-default escaped text rendering. If rich text is required,
sanitize it with a carefully configured, maintained sanitizer and restrict
allowed elements and attributes. Apply the rule at every output context, not
only during input validation.
