# MVP validation

Validated on Python 3.12.14 on Linux: **190 tests passed**, **93.11% line coverage**, **10/10 YAML evaluations passed**. Ruff and `git diff --check` passed; `uv lock --check` confirms the dependency lock is current.

| Boundary | Evidence |
| --- | --- |
| Agent and skills | Strict schemas, version validation, duplicate rejection, empty initial skills, dynamic activation and retrieval terms |
| Typed tools | All 17 mock contracts; malformed/extra/nested input; invalid output; bounded read retries; no write retry; timeout, rate and concurrency limits |
| MCP providers | Actual stdio discovery and invocation for AWS, Azure and GitLab; durable revision-checked mock changes |
| Client MCP facade | Actual stdio client to live loopback FastAPI over HTTP; structured results, authentication, pending writes, candidate-only learning |
| Authorization | Default deny, scope inventory, deny precedence, proposal-only restrictions, explicit low-risk opt-in, mandatory high-risk review |
| Human review | Exact payload/hash, stale config/resource, expiry before and after queueing, concurrent claims, replay prevention, role separation |
| Injection and secrets | Compromised model attempts destructive tool after malicious metadata; no delete executes; authority spoofing, safe errors and credential redaction |
| Knowledge and memory | Provenance, immutable revisions, stale review hashes, candidate quarantine, approved version preservation, ownership and TTL |
| Audit and telemetry | Append-only DB controls, concurrent chain integrity, before/after-side-effect failures, trace hierarchy, metrics, no raw secrets or exceptions |
| Context | Retrieval allowlist/provenance, instruction/data separation, schema-inclusive size limit, oversized document/result handling |

The test suite exercises security enforcement with adversarial model and tool doubles. It does not measure the reasoning quality of a real LLM. Cloud operations are mocks, not live infrastructure changes.

Docker and the VS Code graphical client were not executed in this environment. Their configuration and setup are provided; the underlying REST, CLI and MCP paths were exercised. GitHub CI is configured for Python 3.12 and 3.13; local validation above covers 3.12. PostgreSQL, SSO, distributed limits, externally immutable audit storage and real cloud credentials remain production integration work.

Reproduce from the repository root:

```sh
python -m pip install -c constraints-dev.txt -e '.[dev]'
pytest --cov=harness --cov-report=term-missing
ruff check src tests mcp_servers
harness eval run
```
