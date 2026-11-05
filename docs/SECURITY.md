# Security boundaries and release gates

## Current MVP boundary

CyberX Pro MVP stores organizations, users, assets, authorization records, local task-request records, and audit events. Creating a task record does **not** contact an asset, perform reconnaissance, run a vulnerability check, or execute code on a target. The API status `RECORDED` describes the persistence of a request only.

Do not use this MVP for production data or as a substitute for an independent security review. It does not yet provide MFA, organization membership and RBAC, PostgreSQL row-level policies, a hardened worker runtime, or production-grade rate limiting and monitoring.

## Authorization invariants

- An asset is always resolved within the authenticated user's organization.
- A task request is rejected unless an authorization for that same organization and asset is active at request time.
- Revoked and expired authorizations cannot be used for new requests.
- A rejected request is written to the audit log and committed before the API returns the denial.
- Task creation is metadata-only. No target-side work is performed.

## Application safeguards

- Passwords use scrypt; session tokens are random bearer secrets, while only their SHA-256 digests are stored in SQLite.
- SQL queries use bound parameters.
- Responses include baseline browser security headers and a restrictive Content Security Policy for the current same-origin UI.
- All secret values and real customer data must stay out of source control and demo environments.

## Before any production or execution feature

1. Add role-based access control and MFA, review session lifecycle and rate limits, and test authorization failures against the API directly.
2. Move production data to PostgreSQL; enforce tenant separation in service queries and database policy, and test cross-tenant access.
3. Threat-model uploads, reports, and AI data flows; add encrypted object storage, retention/deletion rules, and access logging.
4. If any assessment executor is proposed, it must be disabled by default and separately reviewed. Require explicit verified scope, authorization re-check immediately before execution, network egress restrictions, resource limits, cancellation, and an auditable allowlist. Never add exploit, persistence, credential theft, destructive, or uncontrolled propagation capabilities.
5. Run independent security review, dependency and image scanning, backup restoration tests, incident-response exercises, and a documented go/no-go review.
