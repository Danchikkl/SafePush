// Intentional synthetic integration demonstration: the agent container
// sees a scoped capability but never receives the mock provider key.
import { existsSync, readFileSync } from 'node:fs';

async function main() {
  if (existsSync('/run/secrets/mock_provider_key')) {
    throw Error('FAIL: provider secret mounted into untrusted agent container');
  }
  const capability = readFileSync('/run/secrets/demo_capability', 'utf8').trim();
  let response;
  for (let attempt = 0; attempt < 15; attempt++) {
    try {
      response = await fetch('http://broker:8787/v1/mock-complete', {
        method: 'POST',
        headers: { authorization: 'Bearer ' + capability, 'content-type': 'application/json' },
        body: JSON.stringify({
          id: 'demo', operation: 'mock_complete',
          prompt: 'Synthetic request with no live credentials', max_output_tokens: 12,
        }),
        signal: AbortSignal.timeout(1500),
      });
      break;
    } catch {
      await new Promise(resolve => setTimeout(resolve, 200));
    }
  }
  if (!response) throw Error('Broker never became ready');
  const body = await response.json();
  if (!response.ok || body.ok !== true || !String(body.result).startsWith('Synthetic provider response')) {
    throw Error('Broker rejected allowed synthetic operation');
  }
  const forbidden = await fetch('http://broker:8787/v1/any-url', {
    method: 'POST',
    headers: { authorization: 'Bearer ' + capability, 'content-type': 'application/json' },
    body: JSON.stringify({ id: 'demo-2', operation: 'fetch_url', url: 'https://example.invalid' }),
    signal: AbortSignal.timeout(1500),
  });
  if (forbidden.ok) throw Error('Broker allowed arbitrary endpoint');
  process.stdout.write('PASS: synthetic API call succeeded via broker; provider key absent in agent container; arbitrary action refused.\n');
}
main().catch(() => {
  process.stderr.write('Synthetic isolated demo failed.\n');
  process.exitCode = 1;
});
