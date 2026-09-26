# Omarchy FaceAuth: agent instructions

## Code Review Rules

For automated pull-request reviewers (Codex, Claude). Report only what a reviewer adds beyond the agentright gate, which already enforces lint, typecheck, formatting, duplication, and the debt ratchet.

- Report correctness bugs, security issues, data-handling problems, and broken contracts. Skip style and formatting.
- Every finding names the file and line in the diff and a concrete failure: the input or state, and the wrong result. No speculative "consider" notes.
- Rank findings by severity. If nothing clears that bar, say so in one line.
- Never propose editing or relaxing governance files to make a check pass: `.agentright-debt-baseline.json`, the `checkrepo-*.json` ledgers, `agentright.toml`, or hook configuration.
- Flag code that could expose personal or client data, credentials, or licensed third-party data in logs, errors, fixtures, or output. Never quote such values in a comment.
