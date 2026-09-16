# Broken Access Control

VulnLab includes isolated access-control comparison routes for authorized
local testing. The vulnerable routes simulate authentication with the
`X-VulnLab-User` header but omit the ownership check. The secure routes scope
the MongoDB operation to the caller's `ownerId`.

This demonstrates why authentication alone is not authorization: knowing who
the caller is does not grant access to every password record.

The training header is not a production authentication mechanism. A secure
deployment must use a verified session or token, enforce authorization on
every object operation, and return a consistent not-found response when a
caller cannot access a resource.
