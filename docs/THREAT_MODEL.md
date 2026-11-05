# MCP-SPM Threat Model

This document summarizes the M0 threat model for MCP-SPM. The scanner and the policy proxy are both in scope because both are security-critical components.

## Assets
- MCP server inventory and its historical snapshots.
- Approved and drifted tool definitions, schemas, and scopes.
- Process and configuration metadata for local and remote hosts.
- Provenance and trust information for packages and publishers.
- Audit logs and approval records.
- Generated findings and SARIF exports.
- Policy definitions used by the optional proxy.

## Trust boundaries

1. User host and local configuration files.
2. Local client config and process metadata.
3. Containerized or remote MCP servers.
4. Package registries and provenance providers.
5. The scanner itself, including document parsers and AST analyzers.
6. The policy proxy and its enforcement decisions.
7. Storage and database layer.
8. API and UI surfaces that read or write posture metadata.

## STRIDE analysis

### Spoofing
Threats:
- package or publisher typosquatting
- server metadata impersonation
- malicious configuration pointing to a rogue endpoint
- false claims of approval or provenance

Mitigations:
- provenance checks with registry identity verification
- hash-chained snapshots and immutable approval records
- strict allowlisting for remote target scanning
- explicit approval by human reviewers

### Tampering
Threats:
- tool description or schema changes after approval
- modified YAML rules or scanner output
- policy mutation without a new approval
- audit log rewriting

Mitigations:
- canonical JSON snapshots with SHA-256 hashing
- chain hashes linking each snapshot to the previous one
- append-only audit log semantics
- read-only or signed storage patterns for approvals and findings

### Repudiation
Threats:
- claim that a server was approved when it was not
- claim that a finding was suppressed or remediated without evidence
- false attribution of policy decisions

Mitigations:
- actor and timestamp on every approval, policy change, and audit event
- signed or at least tamper-visible records in the storage layer
- reproducible scan metadata including scanner version and rule set version

### Information disclosure
Threats:
- secrets kept in logs or snapshots
- leaked environment values or credentials from config discovery
- schema or tool descriptions exposing internal paths or tokens
- privileged errors from proxy enforcement surfacing internal data

Mitigations:
- redact secrets at ingestion and in SARIF output
- avoid storing raw secrets or environment values by default
- default to least-privilege access and log sanitization
- restrict dashboard/API access to authorized operators

### Denial of service
Threats:
- malicious or oversized schema payloads
- pathologically nested or recursive ASTs
- hostile tool descriptions that trigger expensive parsing or embeddings
- slow or hanging network probes to non-allowlisted endpoints

Mitigations:
- resource limits and timeouts for all server connections
- size and depth limits for parsed schemas and text inputs
- concurrency caps and fail-fast behavior
- banned network egress for scanning containers unless explicitly enabled

### Elevation of privilege
Threats:
- the scanner runs commands or reads local files beyond the intended scope
- the proxy bypasses allowlists or approval status
- an attacker manipulates policy generation from a drifted snapshot
- a user with dashboard access gains dangerous control over enforcement

Mitigations:
- no automatic execution of untrusted server code on the host
- run detection and source analysis in isolated containers with restricted capabilities
- fail closed in `enforce` mode when policy or approval state is unknown
- separate approval permissions from fleet read permissions
- enforce least privilege for CLI and API plans

## Scanner as an attack target

The scanner is a primary security boundary and therefore an attack target. The tool must assume that all inputs are adversarial.

### High-risk inputs
- tool descriptions
- schema descriptions and defaults
- package metadata and lockfiles
- discovered config YAML or JSON
- code and manifest text extracted from untrusted repositories
- optional LLM outputs used to triage or summarize findings

### Attack patterns to harden against
- prompt injection via instructions hidden in tool metadata
- Unicode re-encoding tricks to hide malicious text
- path traversal in local file discovery or rule processing
- parser bombs or malicious YAML that trigger deep recursion or CPU exhaustion
- remote registry poisoning or malicious package metadata
- secrets being exfiltrated through logs or snapshots

### Required controls
- treat all tool text as hostile input
- restrict scanner execution to a sandbox with no host network by default
- never feed raw server metadata into an LLM instruction channel
- normalize and inspect text for invisible characters before scanning
- bound parsing, file size, and recursion depth
- log only redacted evidence and truncated text snippets
- reject or quarantine rules that cannot be validated against fixtures

## Threat assumptions
- Attackers may control or influence MCP server metadata or descriptions.
- Attackers may attempt to weaponize natural-language instructions embedded in schemas.
- Attackers may coerce users into connecting to networked endpoints without explicit allowlisting.
- Attackers may distribute typosquatted packages or republish benign tools with malicious metadata.
- Components storing posture data may be targeted for tampering.

## Security design principles
- Defensive tooling only; no automation that turns untrusted input into execution.
- Zero trust between discovery data and trusted approval state.
- Explicit allowlisting before remote scanning.
- Human approval required for any state transition to approved.
- Fail closed on drift, malformed input, or missing provenance evidence.
- Redaction first; evidence is useful only when it does not leak secrets.

## M0 residual risks
- Package provenance may be incomplete or weak unless registry support is available.
- Semantic classification can be useful but cannot replace deterministic checks.
- Hash-chained snapshots protect against tampering in the storage layer but do not replace backup integrity controls.
- The policy proxy can fail closed but still depends on the correct model of the approved snapshot.

## M0 security acceptance criteria
For the initial implementation boundary, the project should satisfy these conditions:
- no automatic execution of untrusted server code on host systems
- no secrets in logs or snapshots
- remote scanning requires explicit allowlisting
- approval state is human-only
- policy enforcement blocks drifted or unknown definitions in enforce mode
- the scanner itself is isolated from privileged host resources by default
