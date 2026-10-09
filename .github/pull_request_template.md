## Summary

<!-- What changed and why, written for a reader who never saw the session. Add "Fixes #N" when an issue exists. -->

## Evidence

<!--
Fill every field from what ran before you opened the PR; not_verified is required ("none" only if everything ran).
Anything that can only run after the PR opens goes in not_verified; update the block once it has run.
What to show by type:
  fix       a test named for the bug, failing before the fix (red) and passing after (green), plus a re-run of the original failing scenario
  feature   tests for the new behavior, plus a demo run
  docs      the rendered output
  content   the rendered output; flag dated facts and link sources
  config    the affected command before and after, or a dry run
  workflow  actionlint output; this PR's own workflow run once it has run
  deps      the advisory ID if any, tests green, and a smoke run
  refactor  unchanged tests green, plus a note on why behavior is the same
-->

<!-- pr-evidence:v1 -->

```yaml
type: # fix | feature | docs | content | config | workflow | deps | refactor
fixes: [] # review thread ids, issue numbers ("#12"), or a one-line description
tests: [] # for a fix: - {id: <test id>, red: {sha: <pre-fix sha>, exit: 1}, green: {sha: <fix sha>, exit: 0}}
gate: { sha: "", cmd: "", verdict: "" } # the exact gate command you ran, normally "agentright gate"
in_use:
  kind: # cli | ui | log | screenshot | api | render | dry-run | none
  cmd: []
  result: ""
not_verified: "" # what wasn't checked, and why
```

<!-- /pr-evidence -->
