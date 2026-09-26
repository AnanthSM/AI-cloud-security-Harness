# VS Code and AI-client integration

The core runs through REST, CLI, or MCP and does not depend on VS Code. The bundled stdio MCP facade lets an AI client discover the agent, run its mock-model demo, propose typed actions through governance, and create candidate knowledge.

## Start the API

Install the project and generate distinct API tokens as described in the README. Start `harness serve` in a trusted terminal with both token environment variables configured. The server listens on `http://127.0.0.1:8000` by default. The facade only needs the **operator** token; never pass the reviewer token to VS Code, an AI assistant, or its tools.

The API and the local CLI use different fixed user personas. Create and continue a client session through the API/MCP facade. A session ID from `harness run` cannot be adopted by the API operator.

## Configure the MCP facade

Create `.vscode/mcp.json` using the absolute path to the installed virtual-environment executable. This example is for VS Code's local MCP integration:

```json
{
  "inputs": [
    {
      "id": "harnessOperatorToken",
      "type": "promptString",
      "description": "Cloud Security Harness operator token",
      "password": true
    }
  ],
  "servers": {
    "cloud-security-harness": {
      "type": "stdio",
      "command": "/absolute/path/AI-cloud-security-Harness/.venv/bin/harness",
      "args": ["mcp"],
      "env": {
        "HARNESS_API_URL": "http://127.0.0.1:8000",
        "HARNESS_OPERATOR_TOKEN": "${input:harnessOperatorToken}"
      }
    }
  }
}
```

On Windows, use a path such as `C:/src/AI-cloud-security-Harness/.venv/Scripts/harness.exe`. Keep token values out of checked-in configuration. VS Code supports workspace MCP configuration and secret input variables; consult the [official MCP setup and configuration documentation](https://code.visualstudio.com/docs/agent-customization/mcp-servers) for your installed client. Current Agent Host sessions have different configuration forwarding rules and do not forward servers requiring interactive input variables; configure that host's supported secure credential mechanism instead of copying a reviewer credential into a file.

Start the configured server through VS Code's MCP controls, review its configuration, and enable the tools you intend to use. The facade communicates over stdin/stdout and sends HTTP requests to the already running API; it does not start the API itself. Keep stdout reserved for MCP protocol traffic.

## Available client tools

| Tool | Purpose |
| --- | --- |
| `list_agents` | Inspect the declarative agent catalog |
| `list_tools` | Inspect registered schemas and risk classes |
| `run_agent` | Run the internal deterministic mock model and return a session ID |
| `propose_action` | Submit an external model's tool proposal to the same governance service |
| `learn` | Create candidate knowledge from an owned session |

There are intentionally no client tools for approving actions, promoting knowledge, reading credentials, or running a shell. Review takes place in a trusted local terminal or a separate human application using the reviewer API.

## Investigation and review

Ask the client to call `run_agent` with:

```json
{
  "agent_id": "cloud-security-agent",
  "prompt": "Check whether sg-12345 allows SSH from the internet."
}
```

Keep the returned `session_id`. A follow-up `run_agent` request for removal returns a pending approval, not an executed change. Alternatively, a client can inspect `list_tools` and submit its own validated proposal:

```json
{
  "session_id": "SESSION_ID_FROM_API",
  "agent_id": "cloud-security-agent",
  "tool": "aws.get_security_group",
  "arguments": {
    "account_id": "111111111111",
    "region": "us-east-1",
    "security_group_id": "sg-12345"
  }
}
```

For a modification, use the resource revision observed in that read. The harness determines risk and environment from trusted definitions; neither should be supplied as authorization claims in the arguments. The human reviewer checks the full approval payload and uses its current `payload_hash` to approve execution. A new read can verify the mock resource after approval.

This gives Copilot or another model two useful modes: the internal mock agent demonstrates the full runtime; direct action proposals let the external model reason while the harness remains the execution authority. Neither mode installs a real LLM provider inside the harness.

## Learning and custom UI

`learn(session_id=...)` and an API `run_agent` request whose prompt is exactly `/learn` both create a candidate. Review and promotion still require the separate reviewer workflow. The terminal command `harness learn` learns from the latest local CLI session, or from `--session` explicitly.

This repository does not register a global VS Code `/learn` chat command or install a custom agent-selector button. A future prompt file or extension can provide that presentation layer and invoke these existing APIs. Keep the UI adapter independent of the runtime, show exact proposed changes, preserve session ownership, and keep review credentials outside model-accessible state.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| MCP process cannot start | Absolute executable path and virtual-environment installation |
| Connection refused | API is running at `HARNESS_API_URL` and reachable from the host running MCP |
| HTTP 403 | Correct operator token, at least 32 characters, distinct from reviewer token |
| Session access denied | Continue the API-created session with the same API persona |
| Approval conflict | It expired, was already claimed, or configuration/resource state changed; review a new proposal |
| No real model response | The bundled provider is a deterministic mock; use external proposals or implement a model adapter |

Never expose a cloud-provider mock server directly as the assistant's production tool endpoint. The assistant should connect to the governed facade; provider MCP servers sit behind the harness authorization boundary.
