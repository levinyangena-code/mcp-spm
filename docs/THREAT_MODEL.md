# MCP-SPM Threat Model

MCP-SPM is defensive assessment software that ingests potentially malicious configurations, MCP metadata, source code, and network responses. Its scanner, storage, reporting pipeline, and future API are security-sensitive attack surfaces. This M0 document describes risks and required design controls; it does not claim they are implemented.

## Scope and security objectives

Protect the host running MCP-SPM, target systems, credentials, assessment integrity, historical results, and report consumers. Preserve explicit authorization boundaries, prevent untrusted input from causing code execution or network access, and produce evidence that is useful without leaking secrets. Static assessment is the default; active assessment requires explicit authorization; isolated dynamic assessment is opt-in and sandboxed.

## Assets
- MCP server/configuration inventory and historical tool definition fingerprints.
- User credentials, environment variables, tokens, local paths, and configuration data.
- Assessment scope and target allowlist.
- Rule definitions, scanner binaries/dependencies, findings, evidence, and reports.
- SQLite/PostgreSQL database, migrations, audit/history records, and trusted baselines.
- Future API identities, authorization policy, and scheduling configuration.

## Trust boundaries
1. User-provided config files, manifests, source trees, and command arguments.
2. Local host files, processes, and MCP stdio servers.
3. Networked MCP servers and their protocol responses.
4. Package registries, publisher identities, and provenance services.
5. Rule files, plugins, parsers, and the assessment engine.
6. Optional LLM/classifier services, if explicitly introduced.
7. Local database and report outputs.
8. Future REST API and dashboard clients.
9. Disposable dynamic-assessment sandbox and its host/container runtime.

## STRIDE analysis

### Spoofing
**Threats:** a lookalike server or package, spoofed publisher metadata, DNS rebinding, configuration pointing to an unauthorized endpoint, or an untrusted fingerprint being presented as an approved baseline.

**Controls:** require explicit remote target allowlisting; bind authorization to the resolved destination and revalidate after DNS changes and redirects; record provenance and source of observations; distinguish observed fingerprints from human-trusted baselines; authenticate future API clients.

### Tampering
**Threats:** malicious changes to tool descriptions or schemas, config/rule mutation, modified historical records, manipulated scan output, or unauthorized changes to API policy and remediation status.

**Controls:** deterministic versioned canonicalization; SHA-256 fingerprints and historical comparison; transactional database writes; schema migrations; least-privilege storage; record scanner/rule versions; human review of changes. A content hash detects changed content but does not authenticate its publisher. Hash chaining alone does not prevent an administrator who controls the database and backups from rewriting history.

### Repudiation
**Threats:** disputes over whether an assessment ran, which scope it used, who approved a baseline, or why a finding changed status.

**Controls:** record scan mode, scope, tool/rule versions, timestamps, result status, and human reviewer identity where available. Keep finding instance IDs separate from rule IDs. Preserve enough sanitized evidence to reproduce decisions without retaining secrets. Never represent a failed or skipped scan as successful.

### Information disclosure
**Threats:** secrets in configs, process arguments, protocol responses, evidence, logs, database fields, reports, or HTML; local filesystem paths and private tool descriptions exposed through API/report access.

**Controls:** redact at ingestion and before persistence; do not retain raw environment values by default; bound and truncate evidence; escape untrusted HTML; restrict report/database permissions; avoid logging request bodies and credentials; authenticate and authorize future API access. Redaction failures should prevent persistence or export of the affected value.

### Denial of service
**Threats:** huge or deeply nested schemas, slow/hanging servers, decompression or parser bombs, excessive tool lists, pathological source files, regex backtracking, unbounded concurrency, or expensive scoring/report rendering.

**Controls:** timeouts and cancellation; request/response and file size caps; schema/text depth and item-count limits; bounded concurrency; safe YAML/JSON parsing; regex safeguards; per-stage CPU/memory/time budgets; graceful partial-failure reporting. Dynamic assessment also has container resource limits.

### Elevation of privilege
**Threats:** executing a launch command from discovered config, arbitrary code execution through dynamic testing or a parser/plugin, SSRF reaching privileged services, unsafe file path handling, proxying beyond policy, or an API user acquiring scan/approval privileges.

**Controls:** do not execute commands by default; make active stdio launches explicit and validated; run untrusted code only in disposable containers with no network by default, read-only filesystem, dropped capabilities, and strict limits; protect filesystem access against traversal and symlink escapes; validate and revalidate network scope, including redirects and resolved IP addresses; use least privilege and role separation for future API operations. Dynamic assessment never runs on the host.

## Scanner as an attack target

Assume every external byte is adversarial: MCP descriptions, schema fields, annotations, resources, prompts, protocol messages, configuration files, manifests, source archives, package metadata, registry responses, rule fixtures, and optional model output.

Required design controls:
- Keep untrusted text in data channels, not instruction channels. If optional LLM triage is added, use fixed instructions, quoted hostile content, schema-constrained output, and no authority to call tools, change severity autonomously, or approve baselines.
- Parse safely with strict limits and no unsafe object deserialization or evaluation.
- Use safe path handling for all file discovery and report generation; prevent traversal and symlink escape.
- Keep network off for static analysis and sandbox execution by default. Active network requests require explicit allowlisting and SSRF controls.
- Prevent arbitrary shell/process execution by default; discovered command strings remain inert data.
- Redact before logs, evidence, snapshots, and reports; test redaction with secret fixtures.
- Escape all untrusted content in HTML and terminal output.
- Validate rule schemas and fixture references before loading rules; plugins require explicit trust and version compatibility.
- Ensure regex and AST analyzers have time/resource bounds and cannot load scanned code.

## Assessment-mode-specific rules

- **Static:** no MCP server launch or network connection; safe to run on recorded fixtures and parsed configuration.
- **Active:** explicit user action and scope validation; remote hosts must be allowlisted. Apply timeouts, response limits, redirect/DNS/IP checks, and no secret-bearing logs. Local stdio servers must not be misclassified as HTTP auth failures.
- **Isolated dynamic:** disabled by default. Require disposable isolation with no host execution, no network by default, read-only filesystem, dropped capabilities, and CPU/memory/time limits. Abort if required isolation cannot be guaranteed.

## Residual risks
- Static analysis can miss behavior that is not represented in available source or metadata; absence of findings is not proof of safety.
- Fingerprints prove equality of canonicalized observed definitions only, not benign behavior, publisher identity, or authenticity.
- Risk scoring is a prioritization aid; contextual MCP scores must be transparent and must not be mislabeled as CVSS.
- Registry and provenance evidence may be incomplete or unavailable.
- Hashes and local history are not tamper-proof against an attacker controlling the host, database, and backups.
- Sandboxing depends on correct configuration and the security of the container runtime and host kernel.
- Active assessment may affect target availability even with strict limits; authorization and scope must be confirmed.

## M0 security acceptance criteria
The design and later implementation must ensure:
- Static mode makes no network requests and launches no server processes.
- Active remote assessment requires explicit allowlisting and SSRF-resistant validation.
- Local stdio is assessed with transport-appropriate checks, not HTTP-only assumptions.
- Dynamic testing is disabled by default and isolated from the host.
- Secrets are redacted before logs, storage, evidence, or reports.
- Hostile text and protocol responses cannot trigger execution, tool calls, or approvals.
- Findings and fingerprints are auditable and clearly distinguish observation from trust.
- No feature, scan result, test coverage, or security guarantee is represented as implemented until verified.
