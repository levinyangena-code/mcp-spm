# MCP-SPM Detection Rule Specification

This document defines the first rule catalog and the contract expected of assessment rules. Rules are detection logic, not proof that a server is exploitable. All rules must operate within the assessment scope and safe-input requirements in `CLAUDE.md` and `docs/THREAT_MODEL.md`.

## Rule contract

Each rule must provide:
- A unique stable identifier (`SPM-NNN`), name, description, and target/input category.
- Severity (`critical`, `high`, `medium`, `low`, `informational`) and confidence (`low`, `medium`, `high`).
- Deterministic detection logic, including transport applicability and known limitations.
- Evidence that is redacted before persistence/output and bounded in size.
- Remediation guidance and automated tests.
- Optional CVSS mapping only when applicable; contextual MCP-specific risk must be labeled separately.

Suggested declarative shape:

```yaml
id: SPM-005
version: 1
name: Suspicious tool description
category: tool_metadata
description: Detects agent-directed or exfiltration-oriented language in tool metadata.
severity: high
confidence: medium
applies_to: [description, schema_descriptions]
transports: [stdio, sse, streamable_http]
detector:
  type: deterministic
  normalize: [unicode_nfkc, strip_zero_width, casefold]
evidence:
  redact_secrets: true
  max_chars: 200
remediation: Describe tool behavior without instructions directed at an AI agent.
references: []
tests:
  positive: [fixtures/rules/SPM-005/positive.json]
  negative: [fixtures/rules/SPM-005/negative.json]
```

The exact parser/schema is to be established during foundation implementation. Rule IDs are distinct from unique finding-instance IDs.

## Severity and risk contract

Severity levels are critical, high, medium, low, and informational. Findings also include exploitability, potential impact, exposure, confidence, evidence, and remediation. Where a specific CVE or applicable vulnerability supports it, include CVSS version, vector, and score with source. Otherwise calculate a separate, documented MCP-SPM contextual score from explicit inputs; do not call it CVSS. Keep scoring inputs and rationale in the report so results can be reproduced. Risk score is prioritization, not a guarantee or exploitability claim.

## Initial rule catalog

| ID | Name | Primary detection intent | Important applicability/limitations |
|---|---|---|---|
| SPM-001 | Exposed secrets and credentials | Detect credential-like values in configs, environment references, metadata, or source evidence. | Redact immediately; reports must not reproduce matched secret values. Distinguish references to environment variable names from actual exposed values. |
| SPM-002 | Weak or missing authentication controls | Assess authentication requirements and relevant OAuth/resource/audience validation for network transports. | Do not report missing HTTP authentication for local stdio. State when authentication cannot be determined from static evidence. |
| SPM-003 | Excessive permissions | Identify declared or observed capabilities broader than the stated tool purpose or policy. | Findings are contextual; explain which capability and evidence led to the assessment. |
| SPM-004 | Potentially dangerous command execution | Identify tool interfaces or source evidence suggesting unrestricted shell/subprocess execution. | Static detection indicates a capability or unsafe pattern; it must not execute the command or claim exploitability without evidence. |
| SPM-005 | Suspicious tool descriptions and poisoning indicators | Detect agent-directed instructions, secrecy directives, exfiltration phrasing, or suspicious hidden metadata. | Treat content only as hostile data; normalization must preserve a way to show original offsets safely. |
| SPM-006 | Unexpected tool schema modifications | Compare canonical schema fingerprints with a trusted historical baseline and report changes. | A change is not automatically malicious. Baseline trust/re-approval is human-only. |
| SPM-007 | Insecure transport configuration | Detect plaintext or otherwise unsafe network transport configuration and insecure bindings. | Apply only to relevant network transports; distinguish loopback/local transports and explain scope. |
| SPM-008 | Supply-chain security risks | Identify missing/invalid signature or provenance evidence, suspicious package identity, or publisher changes where data is available. | Missing evidence is not proof of compromise; include evidence source and uncertainty. |
| SPM-009 | Sensitive information exposure | Detect tool/config behavior or metadata that could disclose sensitive files, environment data, or response content. | Do not read protected data to prove exposure; use static/config evidence and redact findings. |
| SPM-010 | Insufficient security auditing | Identify missing audit configuration or inadequate evidence of security-relevant activity logging. | Report only when configuration/source evidence supports the conclusion; absence of observed logs is not proof they do not exist. |

## Finding output contract

Every finding instance should contain:
- Unique `finding_id` and stable `rule_id`.
- Server/asset identifier, optional tool identifier, scan identifier, and source location.
- Severity, confidence, exploitability, impact, exposure, and risk model/version.
- Redacted, bounded evidence and evidence source; never store the secret value that triggered a detector.
- Remediation, status, first/last observed times, and a stable fingerprint for comparison/deduplication.
- Optional CVSS details with clear provenance when applicable.

## Test requirements

Every rule must include automated tests for:
- True positive: representative matching input.
- True negative: legitimate benign input, including a realistic case near the detector boundary.
- False-positive regression: a known benign case that previously or plausibly could match.
- False-negative regression/evasion: a documented variant the detector is expected to catch or a limitation explicitly recorded when it cannot.

The rule test suite should validate schema, unique IDs, fixture references, expected findings, and safe evidence redaction. Tests use recorded fixtures, never live network targets. Describe detection limitations and keep fixtures reproducible. Deliberately vulnerable MCP labs are separate test assets, must be clearly labeled, and bind to `127.0.0.1` only.

## Assessment boundaries

Rules do not authorize a scan or connection. The assessment pipeline validates configuration and scope before running discovery or active checks. Static rules cannot launch commands or contact targets. Active checks require explicit authorization; remote targets require the allowlist. Dynamic checks are disabled by default and isolated. Findings for authentication, transport, and exposure must state the applicable transport and avoid applying HTTP assumptions to stdio deployments.

## Future compatibility

This initial SPM-001 through SPM-010 catalog is the user-facing starting set. The earlier category labels (`DISC`, `POIS`, `PRIV`, `SCHEMA`, `CODE`, `DRIFT`, `PROV`) may be used as internal tags or detector families, but must not replace the stable SPM IDs without an explicit migration plan. OWASP MCP Top 10, CVSS, and SARIF mappings should be verified against the versions actually supported by the implementation.
