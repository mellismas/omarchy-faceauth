# TODO

Follow-ups recorded from code review that this repository can't fix on its own. Each entry says whether it was reproduced.

## codeowners-case-variants

Unverified. Raised in the review of #44 (finding N-1, rated P1, security) and recorded out of scope there.

GitHub matches CODEOWNERS paths case-sensitively and supports no character classes, so the `.gitleaks*` entry doesn't route a case variant such as `.GITLEAKSIGNORE` or `.Gitleaks.toml` to the owner. On a case-insensitive checkout (Windows, or macOS by default), a plain `gitleaks` run would open such a file as its ignore list or config. agentright's pre-push scan reads the exact lowercase names from the trusted base in git, so the push gate isn't affected. The same limit applies to every other entry in `.github/CODEOWNERS`.

The fix belongs outside this repository: the PR shepherd could match governance paths case-insensitively, or a check could refuse case variants of those names. Not reproduced, because no case-insensitive checkout with gitleaks was available.
