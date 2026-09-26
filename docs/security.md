# Security model and operating limits

The core rule is: **models propose; the harness authorizes; tools execute**. The model is untrusted for authorization. Prompts, tool descriptions, tickets, logs, repository text, and retrieved documents cannot grant a capability or approve a write.

## Trust boundaries

| Boundary | Trusted authority | Untrusted input |
| --- | --- | --- |
| API identity | Locally configured operator/reviewer token mappings | Caller-supplied bodies and authorization headers |
| Agent capabilities | Operator-reviewed agent YAML | Model-selected agent descriptions or tool names |
| Tool risk and schemas | Local tool registry | MCP metadata and tool output |
| Environment | Operator-maintained resource-scope inventory | Claimed environment in prompts or resource tags |
| Execution | Governed tool service, exact approval claim | A model's request or statement that approval occurred |
| Knowledge | Reviewed SQL versions and administratively provisioned files | Candidates, imported external content, session notes |
| Audit | Application append-only operations and SQLite triggers | Arbitrary event payloads or mutable log files |

The repository, configuration, local database, executable, and OS account form the local administrative trust boundary. An actor who can modify application code or run arbitrary code as its OS owner can bypass application controls. Do not expose the local CLI or reviewer credential as an AI tool.

## Identity and review

The API accepts separate bearer credentials in `HARNESS_OPERATOR_TOKEN` and `HARNESS_REVIEWER_TOKEN`; each configured credential must contain at least 32 characters, and they must differ. Generate independent random values. The MVP maps these to fixed `api-operator` and `api-reviewer` personas. It does not implement SSO, multiple employees, organizational separation of duties, MFA, token issuance, or token expiry.

Operator tokens can run investigations, propose governed actions, inspect their own approvals, and create learning candidates. Reviewer credentials can inspect approval and candidate queues, approve/reject actions, and modify/promote/reject knowledge. Approvals are tied to the submitted exact hash and revalidated against current control-plane state. A reviewer token is a bearer authority; the application cannot determine whether a human or code used it.

The local CLI deliberately assumes a trusted human OS operator and uses local operator/reviewer personas. Its interactive confirmation provides review ergonomics, not a separate authentication boundary. Sessions created through CLI and API have different owners and cannot be used interchangeably. The AI-facing MCP facade receives only the operator token and exposes no approval or promotion methods.

Keep the API on loopback for local use. A remote deployment needs TLS, authenticated ingress, rate limits, CSRF consideration for any future browser UI, and an identity provider. `/health` and OpenAPI documentation describe the service; they do not execute actions. Authenticated application routes remain protected.

## Execution defenses

- Strict JSON-schema validation rejects extra or malformed input and validates returned structured data.
- The local registry owns risk; the model cannot change it. Unknown tools, agents, scopes, and unmatched policy requests fail closed.
- Policy rules use deny-overrides. All writes require review in the bundled configuration. High-risk writes always require approval, and destructive operations are denied. Low-risk automatic execution requires an explicit tool-group grant, `default_permissions.low_risk_write: allow`, and matching YAML rules that all permit the action; proposal permission alone cannot enable it.
- Approval records bind exact arguments, user/session, resource, risk, agent/tool definitions, and policy revision. Changing any authorization context requires a fresh request.
- SQLite transactions atomically claim each approval once. Approving the same request twice cannot execute it twice.
- Mock writes use resource revisions. Reads have bounded retry; writes, including destructive tools, never automatically retry.
- Per-process rate, concurrency, timeout, model-step, and context-size limits bound local execution.
- Only fixed, operator-configured MCP subprocess commands run. The default agent has no shell, filesystem-write, or credential-discovery capability.

Timeout and cancellation do not prove that a remote write failed. An approved action with an uncertain outcome stays claimed and must be reconciled against provider state before any new proposal. Opted-in low-risk writes have no approval claim; their uncertain outcomes are audited and also require reconciliation. There is no automatic rollback, universal cloud idempotency key, distributed job lease, or cross-provider transaction. The mock's conditional revision is a demonstrated pattern, not a guarantee for future integrations.

`default_permissions.low_risk_write` defaults to `approval_required` and also accepts `allow` or `deny`. The existing `write: deny` remains an overriding block. Neither a matching approval rule nor a denial can be bypassed by adding an ALLOW rule. An operator could explicitly enable a narrowly scoped development issue-creation workflow, but would need to grant the provider's write group and review all matching policy restrictions. The bundled agent has only read groups, and bundled production writes still require review. Opted-in low-risk writes retain validation, current-policy checks, auditing, and the no-write-retry rule.

## Prompt injection

Tool responses and session data enter context in explicit data envelopes. Reviewed documents are also data rather than executable instructions. The context manager uses bounded retrieval and tracks included document versions. The model can still misunderstand malicious text; the security guarantee comes from independent authorization on every proposed action.

The injection tests include malicious response text and an adversarial model proposal so success does not depend solely on the deterministic demo model ignoring bad instructions. A malicious request to delete resources remains denied by governance. Adding a real model still requires model-specific evaluations for reasoning quality, data leakage, tool arguments, and unsafe follow-on behavior.

## Secrets and data handling

`SecretProvider` abstracts credential acquisition; `EnvironmentSecretProvider` is the initial adapter. No cloud credentials are needed by the bundled mocks. Provider credentials belong to adapters and must never become model tool arguments, YAML settings, skill text, or knowledge content. Future cloud adapters should obtain short-lived, least-privilege credentials through workload identity or a secret broker.

Audit events use a closed schema and store argument hashes instead of argument bodies. Secret-shaped keys, recognizable secret strings, and configured harness credential values are redacted. Raw prompts, tool outputs, exception strings, and HTTP request bodies are not arbitrary audit metadata. Tool/provider errors are sanitized before public exposure.

Sanitization is defense in depth, not universal secret detection or DLP. An unknown secret format may evade heuristics. Session state and knowledge are plaintext local data after sanitization; use OS permissions and encrypted storage when handling sensitive information. Do not submit production credentials as investigation evidence. Retention, encryption-at-rest key management, and formal data classification are future deployment work.

## Knowledge provenance and file access

`/learn` creates a candidate only. Reviewers approve the current hash and version; modification creates a new revision and invalidates stale review. Rejections and old versions remain available in the store's history. A pending candidate never overwrites the active approved revision used for normal retrieval.

Knowledge files are not a general upload API. On startup, new operator-provisioned identities are imported from local folders only after validating their schema, status, provenance, size, and paths. Approved/scenario/policy files must declare completed review; candidate files cannot declare approval. Those fields document local administrative review, not a cryptographic attestation. An untrusted external document must enter through candidate creation and human review, not be copied into a trusted directory with invented review metadata.

## Audit guarantees

Events are append-only through application/ORM operations. SQLite triggers reject updates and deletes, and chained hashes reveal inconsistent alteration. `harness audit --verify` checks the chain. Audit intent is recorded before execution; if this persistence fails, execution does not proceed.

This is **tamper-evident local auditing**, not immutable storage against a database owner. An administrator can drop triggers, replace the database, or recompute a chain; an unanchored chain cannot reliably prove that its tail was truncated. Production needs restricted database roles, externally anchored chain heads or signatures, and an external append-only/WORM sink. Telemetry exports complement audit evidence but are not the authorization ledger.

Console traces and sanitized structured INFO operation events go to stderr by default. `HARNESS_TRACE_CONSOLE=false` disables full trace export, not the structured events; their level and handlers are controlled by `config/logging.yaml`. CLI result JSON remains on stdout.

## Production readiness boundary

The MVP is suitable for local development, architecture validation, and credential-free demonstrations. Before real cloud writes, add independently authenticated reviewers, production resource authority, scoped workload credentials, tenant isolation, durable execution reconciliation, and operational recovery procedures. Test the chosen production database and all provider failure modes. Distribute concurrency/rate limiting across workers, protect configuration changes, and export audit evidence outside the runtime's administrative domain.
