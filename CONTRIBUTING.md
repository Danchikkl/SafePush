# Contributing to SafePush

Thank you for helping developers ship safer apps. Beginners welcome.

## Local setup

```bash
npm install
npm run check
node dist/cli.mjs scan .
```

Open an issue before making large architectural changes. Small pull requests are preferred.

## Add a rule

1. Start with a user problem and an example of the intended remediation.
2. Add a rule to `src/rules.mts` (or an extracted file once more rules exist).
3. Add positive and negative tests in `test/safepush.test.mjs`.
4. Never insert real credentials in test fixtures. Construct clearly fake tokens in code.
5. Ensure no matched secret or surrounding source line is printed, stored or transmitted.
6. Document false positives and what the rule **cannot** prove.

## Good first contributions

- Detect dangerous `NEXT_PUBLIC_`/`VITE_` patterns with fewer false positives.
- Translate findings into other languages.
- Add Windows path handling tests.
- Improve a safe `--fix` preview mode; do not silently modify user code.
- Add integration instructions for Claude Code and Cursor, without requiring their APIs.

## PR checklist

- [ ] Includes focused tests
- [ ] No sensitive values in fixtures, logs, or snapshots
- [ ] No network calls or credential validation
- [ ] Documents limitations and backward compatibility
- [ ] `npm run check` passes

This project is not for scanning strangers' repositories, validating leaked tokens, or contacting people without permission.