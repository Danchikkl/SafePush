# SafePush Agent Security — Research Track

> Design proposal, **not implemented security protection**. No real API keys in test fixtures.

## Goal and trust boundary

Build a separate security layer for AI coding agents. Agent-controlled code and tool execution must not have access to long-lived credentials. A separate trusted process is the only owner of secrets. Never claim that regex/hooks alone enforce confidentiality.

## Implemented v0: synthetic broker (research, not production)

`src/research-broker.mts` implements a **single-process, local JSON-lines request/response mock**. It reads a *synthetic-only* key from a file outside the configured agent project, accepts only the `mock_complete` operation, rejects arbitrary URLs/operation names, and never echoes the credential or prompt. It reserves the maximum calculated mock cost before processing, limits output tokens and session calls, and reconciles the synthetic charge afterward.

**Important:** Placing a file outside a workspace does **not** make it private if the agent has the same operating-system permissions. This is an interface/budget prototype, not an isolated runtime. No actual API calls, no billable activity, no trusted secret storage, no network controls, and no durable or multi-process budget guarantees are provided.

Try it with a dedicated temporary project directory and a separate *fake* key file (never use live keys):

```sh
npm ci --ignore-scripts
npm run build
mkdir -p /tmp/safepush-agent
printf 'SAFEPUSH_TEST_KEY_SYNTHETIC1234567890\n' > /tmp/safepush-broker-demo-key
printf '%s\n' '{"id":1,"operation":"mock_complete","prompt":"Explain this snippet","max_output_tokens":12}' | \
  node dist/research-broker.mjs --agent-root /tmp/safepush-agent --secret-file /tmp/safepush-broker-demo-key
```

Synthetic cost formula: input units = ceil(UTF-8 prompt bytes / 4), charged at 2 synthetic accounting units; maximum output tokens charged at 3 units each during admission. Session budget = 1000 units, maximum calls = 10, maximum output = 64 tokens. These **are not dollars, accurate provider token counts, or real prices**. The mock response is static and does not contain the prompt or credential.

Test using `npm run check`; the synthetic broker tests verify bounded calls, budget exhaustion, refused passthrough, malformed inputs, and secret location checks.

**Next crucial stage:** validate the optional Docker proof with live container tooling, test stronger transport authenticity and agent-client integration, and replace single-process counters with durable, atomic reservations before introducing multiple broker instances or billable provider calls.

## Validated security building blocks integrated into prototype

The broker now uses a small, explicit **capability allowlist** (`src/research-policy.mts`) and an admission-control **budget invariant**, rather than a speculative risk score. Requests are validated against a fixed operation schema; unknown operations, URLs, headers, or excessive output are rejected.

For every admitted mock request, its worst-case *synthetic* cost is reserved synchronously before dispatch. Outstanding reservations reduce available units; a successful settlement returns only the unused allocation; a provider failure with uncertain billing forfeits the full reservation. Invalid settlements, repeated settlements and exceeding the per-session call count are denied. Synthetic regression tests cover concurrent reservations within a single process, Unicode byte limits, refund abuse, and call exhaustion.

This approach uses standard security engineering principles (least privilege, complete mediation, fail-closed admission and resource quotas). **It is not mathematical proof of noninterference or a production billing guarantee.** External providers may bill differently, reserve/settle is only single-process/in-memory, and the agent is not yet sandboxed. CUSUM and queueing models are deliberately deferred until we have measured normal operation and a real source of usage data.

## Experimental isolation demo — Docker Compose

An optional **synthetic-only** HTTP broker now demonstrates separation of the agent from a mock provider credential. It is implemented in `src/research-http-broker.mts`, with an isolated network demo in `research/compose.yaml`.

```sh
# Requires Docker Engine and Docker Compose; no real API keys or provider network calls.
docker compose -f research/compose.yaml up --build --abort-on-container-exit --exit-code-from agent
docker compose -f research/compose.yaml down
```

The Compose demo uses an `internal: true` network with **no published host ports**. The untrusted `agent` service runs as a non-root user, with a read-only filesystem, all Linux capabilities dropped, no-new-privileges, and resource limits. The mock provider key is mounted into the **broker container only**. The agent receives a separate, deliberately limited **synthetic capability credential** to call the broker; this credential is not a provider API key. The agent client checks that the mock provider-key mount is absent and that the broker refuses an unapproved action.

The broker's only HTTP endpoint is `POST /v1/mock-complete`: it rejects unknown paths, HTTP methods, arbitrary URLs, unknown operation fields, unauthorized calls, oversized JSON requests and exhausted budgets. A shared in-memory `BudgetGovernor` mediates each request **within a single broker process**, including concurrent HTTP requests. Only hardcoded synthetic responses are returned; no outbound provider calls exist. Non-loopback binding requires explicit `SAFEPUSH_RESEARCH_CONTAINER_ONLY=1` opt-in.

**Important limits:** Docker must be installed, configured and running properly. This demo is **not independently attested** and is not tested automatically in standard Node/Windows CI. The agent is a tiny demonstration script, not Claude/Codex itself. Shared demo capability and mock provider fixtures are publicly committed for reproduction and are NOT private. Internal Docker networking is not authenticated encryption; a different compromised container on that network could attack the interface. A scoped caller credential permits authorized requests up to the shared budget. This design does not defend against Docker host compromise, kernel/container escapes, privileged Docker access, malware in the trusted broker, or production provider-billing uncertainties. Never put live credentials in research fixtures.

For a real deployment, require independent OS/container trust boundaries, separately provisioned per-user capabilities, TLS/authenticated transport where appropriate, restricted outbound networking at the OS level, durable atomic per-tenant budget reservations, provider allowlists, short-lived credentials, and an adversarial security review.

## Architecture sketch

```text
Untrusted agent process in isolated workspace (no secret mounts or provider keys)
                  |
         narrow approved RPC
                  |
       Trusted policy + budget broker
            |          |
      action allowlist   usage reservation/accounting
            |          |
       Provider adapter holding least-privilege credential
                  |
        Redacted provider response to agent
```

Isolation must be enforced by OS/container/VM permissions and appropriate network egress controls. The broker must not expose a generic HTTP request tool: otherwise an agent can use its credential as an unrestricted proxy. Instead expose narrow, typed actions with allowlisted provider/model, destination, maximum token/output and tool privileges.

## Two independent threats

1. **Credential exfiltration:** agent learns/prints/transmits a private key. Mitigate by isolating the credential and not making it accessible to the agent's environment.
2. **Credential abuse / bill runaway:** agent can still spend money through approved actions without ever knowing the key. Mitigate with a centrally enforced authorization and budget policy.

A hidden API key does **not** protect the bill if the agent can request unlimited expensive operations from the broker.

## Candidate v0 constraints (configurable, illustrative values only)

- Allowlisted operation IDs and provider endpoints; reject arbitrary URLs and generic passthrough.
- Max input and output tokens **per call**; max calls, tokens, concurrency and estimated cost **per session**.
- Daily/monthly per-project budget enforced by the broker, not agent prompts. Optional approval gates for expensive tasks.
- *Reserve* the worst-case cost before dispatching a request, commit the measured charge afterward and release unused reservation. Account for retries, parallel sessions, streamed calls and uncertain provider usage; fail closed when price/usage data is missing.
- Bounded retries and timeouts; circuit breaker for unusual volume or consecutive errors.
- Provider-side hard limits, scoped keys and account alerts as additional independent layers where supported; some platforms offer only soft notifications and even hard limits may enforce with delay.
- Never store raw provider responses, credentials or source code in analytics. Use coarse aggregates with secret-safe logs.
- Default deny when broker cannot reach its durable budget store. Require atomic budget reservation across processes, not an in-memory counter.

## Milestones

1. **Threat model + fixtures:** document trust boundaries, owner capabilities, bypass attempts. Fake provider and synthetic canary keys only.
2. **Cost governor prototype:** local mock broker with atomic reservation, a fixed allowlisted operation, test budget exhaustion, concurrent requests and retry exhaustion.
3. **Sandbox proof:** separate low-privilege agent runtime from broker process, no mounted key, blocked network egress except narrow broker transport.
4. **Broker with real provider:** opt-in behind explicit user approval; scoped key, provider's own hard budget when supported, independent verification and redacted responses.
5. **Adversarial evaluation:** direct read, shell, env, subprocess, injected instructions, tool-output exfiltration, DNS/HTTP, concurrent billing abuse, sandbox escape attempts. Do not claim formal guarantees from tests.

## Non-goals of initial implementation

No automatic cloud-account administration, arbitrary provider API passthrough, real-key test cases, publishing a 'secure sandbox' claim, or API key validation. The experimental Claude hook in PR #9 is a distinct, lower-assurance mechanism.

## Research questions

- Which provider operations can be represented as *narrow capabilities* rather than general network access?
- How to bound worst-case price for tool calls and agentic multi-step tasks with streaming/retries?
- How to make budget reservations durable and atomic without introducing a privileged cloud service?
- Which sandbox approach is practical across Linux, macOS and Windows, and what are its escape surfaces?
- How to preserve development usability without giving the agent shell/network capabilities in the trusted environment?

## Evaluation success criteria

No canary secret in agent-visible filesystem, env or tool responses across the supported threat model; unauthorized broker operations rejected; no approved request can bypass session limits; concurrent reservations do not exceed configured broker allocation; timeout and error states fail closed; legitimate allowed workflows still pass.

Note: actual provider bills may differ from broker estimates and external provider limits can have enforcement delays.
