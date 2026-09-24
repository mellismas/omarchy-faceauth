#!/bin/bash
# The lock helper: hands the Omarchy tree the daemon resolved to the user's
# session, refuses to run without one, answers 0 only when the compositor
# reports a session lock, and 1 otherwise, whatever the lock command said.
set -uo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
helper=$here/../packaging/faceauth-lock-session
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
# Stubs stand in for timeout and systemd-run: they record the OMARCHY_PATH
# handed over and run the command's stub, which answers from LOCKED and
# LOCK_RC in the environment.
cat > "$tmp/bin/systemd-run" <<'S'
#!/bin/bash
for a in "$@"; do case $a in -E) ;; OMARCHY_PATH=*) echo "${a#OMARCHY_PATH=}" >> "$STUB_LOG";; esac; done
while [[ $# -gt 0 && $1 == -* || ${1:-} == OMARCHY_PATH=* ]]; do shift; done
case $1 in
  */omarchy-shell) exit 0 ;;
  */omarchy-system-lock) echo lock >> "$STUB_LOG"; exit "${LOCK_RC:-0}" ;;
  */omarchy-hyprland-session-locked) [[ ${LOCKED:-0} == 1 ]] && exit 0 || exit 1 ;;
esac
exit 3
S
chmod +x "$tmp/bin/systemd-run"
# The helper calls /usr/bin/timeout and /usr/bin/systemd-run by absolute path;
# run it through a copy with those rewritten to the stubs.
sed -e "s#/usr/bin/timeout 15 /usr/bin/systemd-run#$tmp/bin/systemd-run#g" "$helper" > "$tmp/helper"
chmod +x "$tmp/helper"
fails=0
check() { if [[ $1 == "$2" ]]; then echo "ok - $3"; else echo "not ok - $3 (got '$1', want '$2')"; fails=$((fails+1)); fi; }
run() { export STUB_LOG=$tmp/log; : > "$STUB_LOG"; "$tmp/helper" mellis "${@}" 2>/dev/null; echo "rc=$?"; }

out=$(LOCKED=1 run /home/x/omarchy); check "$out" "rc=0" "a locked session answers 0"
check "$(head -1 "$tmp/log")" "/home/x/omarchy" "the path the daemon resolved is handed to the session"
out=$(LOCKED=1 run); check "$out" "rc=1" "no path is a usage error, not a guess"
check "$(wc -l < "$tmp/log")" "0" "and nothing is run without one"
out=$(LOCKED=0 LOCK_RC=0 run /usr/share/omarchy); check "$out" "rc=1" "a lock command that succeeded without locking gives exit 1"
out=$(LOCKED=0 LOCK_RC=1 run /usr/share/omarchy); check "$out" "rc=1" "a failed lock command gives exit 1"
check "$(grep -c '^lock$' "$tmp/log")" "1" "the lock command is run once"
[[ $fails -eq 0 ]]
