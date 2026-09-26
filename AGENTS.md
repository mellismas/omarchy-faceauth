# Omarchy FaceAuth: agent instructions

## Code Review Rules

For automated pull-request reviewers (Codex, Claude). The agentright gate enforces lint, typecheck, formatting, duplication, and the debt ratchet, but only on pushes from Mike's machine. PRs written in the cloud (Codex cloud tasks, Claude Code on the web) have not run it, so on those, report lint, type, and formatting problems too.

- Report correctness bugs, security issues, data-handling problems, and broken contracts. Skip style and formatting, except on cloud-written PRs (see above).
- Every finding names the file and line in the diff and a concrete failure: the input or state, and the wrong result. No speculative "consider" notes.
- Rank findings by severity. If nothing clears that bar, say so in one line.
- Never propose editing or relaxing governance files to make a check pass: `.agentright-debt-baseline.json`, the `checkrepo-*.json` ledgers, `agentright.toml`, or hook configuration.
- Flag code that could expose personal or client data, credentials, or licensed third-party data in logs, errors, fixtures, or output. Never quote such values in a comment.

## Git Workflow

- Commit early and often on a feature branch, with a clear message for each logical step.
- Open a pull request only when a component is complete and passes the local checks. No checkpoint or work-in-progress PRs: every PR you open triggers automated Codex and Claude reviews.
- Keep each pull request to one component, so reviews stay focused.
