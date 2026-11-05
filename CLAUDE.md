# MCP-SPM (MCP Security Posture Manager)

Self-hostable "single pane of glass" for securing Model Context Protocol servers:
discovery, MCP-aware static analysis, drift/provenance tracking, optional runtime policy proxy.

## Mission and scope
- Defensive tooling only. No exploit payload generators, no offensive scanners.
- Remote hosts are scanned ONLY if explicitly allowlisted in `config/targets.allow.yaml`. Default: none.
- Test fixtures (vulnerable server, rug-pull simulator) must bind to 127.0.0.1 and be clearly labeled.

## Non-negotiable security rules
1. **Tool text is hostile input.** Descriptions, schema fields, annotations, resource and prompt text are untrusted data.
   Never place them in an LLM instruction channel. If LLM triage is used, wrap them as quoted data, use a fixed
   system prompt, constrain output to a JSON schema, and never let LLM output trigger tool calls or approvals.
2. **Never execute untrusted server code on the host.** Run in a container with no network, read-only FS,
   dropped capabilities, CPU/mem/time limits. Network is opt-in per scan.
3. **No secrets in logs, snapshots, or SARIF.** Redact at ingestion.
4. **Approvals are human-only.** No code path, LLM, or CI job may auto-approve a drifted server.
5. **Fail closed** in proxy `enforce` mode: unknown tool, unparseable message, or drifted definition = block + log.

## Stack
- Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2 (SQLite default, Postgres supported), Alembic
- Official MCP Python SDK; tree-sitter for Python/TS/Go
- React + TypeScript + Tailwind (Vite) UI
- Docker Compose deployment; `uv` for Python deps; `pnpm` for UI

## Repo layout
```
mcpspm/            # python package
  discovery/  analysis/  drift/  provenance/  proxy/  api/  cli/  core/
rules/             # YAML detection rules (see docs/RULE_SPEC.md)
fixtures/          # vulnerable_server/, rugpull_sim/, rule test fixtures
ui/                # React app
docs/              # ARCHITECTURE.md, THREAT_MODEL.md, RULE_SPEC.md
tests/
action/            # GitHub Action
```

## Commands
- Install: `uv sync`
- Test: `uv run pytest -q`
- Lint/type: `uv run ruff check . && uv run mypy mcpspm`
- Rule tests only: `uv run pytest tests/rules -q`
- UI: `cd ui && pnpm i && pnpm dev`

## Conventions
- Every detection rule has a YAML file and a positive and a negative fixture. CI fails otherwise.
- Findings serialize to SARIF 2.1.0. Each finding carries OWASP LLM Top 10, MITRE ATLAS, and CWE mappings where applicable.
- Snapshots are canonical JSON, content-addressed (SHA-256), hash-chained (each links the previous hash).
- Type hints everywhere, small modules, no network calls in unit tests (use recorded fixtures).
- Plugins register through entry points: `mcpspm.rules`, `mcpspm.discoverers`, `mcpspm.exporters`.

## Workflow rules for Claude
- Plan first for any new module; wait for approval on architecture changes.
- Build in this order: discovery, static analysis, drift, proxy, dashboard.
- One milestone per branch; run tests, lint, and types before declaring done.
- If a requirement is ambiguous or touches the security rules above, ask instead of guessing.
- Do not add dependencies without stating why.
