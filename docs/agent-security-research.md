# SafePush Agent Security — Research Track

> Design proposal, **not implemented security protection**. No real API keys in test fixtures.

## Goal and trust boundary

Build a separate security layer for AI coding agents. Agent-controlled code and tool execution must not have access to long-lived credentials. A separate trusted process is the only owner of secrets. Never claim that regex/hooks alone enforce confidentiality.

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
