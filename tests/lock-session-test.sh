#!/bin/bash
# The lock helper (fix round 9): it runs the lock commands in the user's
# manager by a route that can never start one (a system unit as the user,
# no PAM session, `systemd-run --user` over the user's own bus), hands the
# session the Omarchy tree the daemon resolved, refuses to run without one,
# checks the pinned sessions before every call, and answers whether the
# lock commands ran. Whether the session is locked is the daemon's
# anchored question; the helper never asks the user's manager.
set -uo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
helper=$here/../packaging/faceauth-lock-session
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/sessions"
# Stubs stand in for timeout and the outer systemd-run (the carrier), for
# the inner `systemd-run --user` (the user's unit) and for the commands.
# The carrier and user-unit stubs record their own options and then run
# what their unit would run, the helper's in-unit pin check included
# (fix round 10), so a session that ends between the helper's check and a
# unit's start stops the call there. The commands answer from LOCK_RC.
cat > "$tmp/bin/systemd-run" <<'S'
#!/bin/bash
echo "outer: $*" >> "$STUB_LOG"
[[ -n ${END_SESSION_IN_CARRIER:-} ]] && rm -f "$SESSIONS/$END_SESSION_IN_CARRIER"
while [[ $# -gt 0 && $1 == -* ]]; do shift; done
exec "$@"
S
cat > "$tmp/bin/user-run" <<'S'
#!/bin/bash
echo "inner: $*" >> "$STUB_LOG"
for a in "$@"; do case $a in -EOMARCHY_PATH=*) echo "path ${a#-EOMARCHY_PATH=}" >> "$STUB_LOG";; esac; done
[[ -n ${END_SESSION_IN_UNIT:-} ]] && rm -f "$SESSIONS/$END_SESSION_IN_UNIT"
while [[ $# -gt 0 && $1 == -* ]]; do shift; done
exec "$@"
S
cat > "$tmp/bin/omarchy-shell" <<'S'
#!/bin/bash
[[ -n ${END_SESSION_AFTER_SHELL:-} ]] && rm -f "$SESSIONS/$END_SESSION_AFTER_SHELL"
echo shell >> "$STUB_LOG"
S
cat > "$tmp/bin/omarchy-system-lock" <<'S'
#!/bin/bash
echo lock >> "$STUB_LOG"; exit "${LOCK_RC:-0}"
S
cat > "$tmp/bin/omarchy-hyprland-session-locked" <<'S'
#!/bin/bash
echo asked-the-manager >> "$STUB_LOG"
S
chmod +x "$tmp/bin/"*
# The helper calls timeout, systemd-run and the commands by absolute path
# and reads logind's records under /run/systemd/sessions; run it through a
# copy with those rewritten to the stubs. Nothing runs unless the copy
# calls none of the real ones: this test never reaches a manager.
sed -e "s#/usr/bin/timeout -k 1 4 /usr/bin/systemd-run#$tmp/bin/systemd-run#g" \
    -e "s#/usr/bin/systemd-run --user#$tmp/bin/user-run#g" \
    -e "s#/usr/bin/omarchy-#$tmp/bin/omarchy-#g" \
    -e "s#/run/systemd/sessions/#$tmp/sessions/#g" "$helper" > "$tmp/helper"
if grep -qE '/usr/bin/(timeout|systemd-run|omarchy-)|/run/systemd/sessions' "$tmp/helper"; then
  echo "not ok - the test copy still calls a real binary or reads the real records; nothing was run"
  exit 1
fi
chmod +x "$tmp/helper"
export SESSIONS=$tmp/sessions
fails=0
check() { if [[ $1 == "$2" ]]; then echo "ok - $3"; else echo "not ok - $3 (got '$1', want '$2')"; fails=$((fails+1)); fi; }
run() { export STUB_LOG=$tmp/log; : > "$STUB_LOG"; "$tmp/helper" "${@}" 2>/dev/null; echo "rc=$?"; }
desktop() { printf 'UID=1000\nTYPE=wayland\n' > "$tmp/sessions/$1"; }

desktop 4
out=$(run alice /home/x/omarchy 1000 4); check "$out" "rc=0" "the lock commands ran: 0"
check "$(grep '^path ' "$tmp/log" | head -1)" "path /home/x/omarchy" "the path the daemon resolved is handed to the session"
check "$(grep -c '^lock$' "$tmp/log")" "1" "the lock command is run once"
check "$(grep -c 'asked-the-manager' "$tmp/log")" "0" "the user's manager is never asked whether it locked"
check "$(grep -c 'PAMName\|--machine' "$tmp/log")" "0" "no PAM session, no machine transport"
check "$(grep -c 'User=alice' "$tmp/log")" "2" "a system unit as the user carries each call"
check "$(grep -c 'XDG_RUNTIME_DIR=/run/user/1000' "$tmp/log")" "2" "to the user's own bus"
check "$(grep '^outer: ' "$tmp/log" | grep -c -- '--property=RuntimeMaxSec=4s')" "2" "each carrier ends itself (round 10)"
check "$(grep '^inner: ' "$tmp/log" | grep -c -- '--property=RuntimeMaxSec=4s')" "2" "and each user unit"
check "$(grep '^outer: ' "$tmp/log" | grep -c -- '--property=KillSignal=SIGKILL')" "2" "each carrier ends at once (round 11)"
check "$(grep '^inner: ' "$tmp/log" | grep -c -- '--property=KillSignal=SIGKILL')" "2" "and each user unit"
check "$(grep -c -- '--expand-environment=no' "$tmp/log")" "4" "no manager expands \$ in the arguments"
check "$(grep '^outer: ' "$tmp/log" | grep -c -- '--property=LockPersonality=yes --property=RestrictSUIDSGID=yes')" "2" "the carrier's sandbox is the daemon's"
out=$(run alice); check "$out" "rc=1" "no path is a usage error, not a guess"
check "$(wc -l < "$tmp/log")" "0" "and nothing is run without one"
out=$(run alice /usr/share/omarchy 1000); check "$out" "rc=1" "no pinned session is a usage error"
out=$(LOCK_RC=1 run alice /usr/share/omarchy 1000 4); check "$out" "rc=1" "a failed lock command gives exit 1"
rm -f "$tmp/sessions/4"
out=$(run alice /usr/share/omarchy 1000 4); check "$out" "rc=3" "the pinned session gone: 3"
check "$(wc -l < "$tmp/log")" "0" "and nothing is run"
desktop 4
out=$(END_SESSION_AFTER_SHELL=4 run alice /usr/share/omarchy 1000 4); check "$out" "rc=3" "the session ends between the calls: 3"
check "$(grep -c '^lock$' "$tmp/log")" "0" "and the second call is not made"
desktop 4
out=$(END_SESSION_IN_CARRIER=4 run alice /usr/share/omarchy 1000 4); check "$out" "rc=3" "the session ends as the carrier starts: 3 (round 10)"
check "$(grep -c '^inner: \|^shell$\|^lock$' "$tmp/log")" "0" "and the carrier reaches nothing"
desktop 4
out=$(END_SESSION_IN_UNIT=4 run alice /usr/share/omarchy 1000 4); check "$out" "rc=3" "the session ends as the user's unit starts: 3"
check "$(grep -c '^shell$\|^lock$' "$tmp/log")" "0" "and the unit runs no command"
printf 'UID=1001\nTYPE=wayland\n' > "$tmp/sessions/4"
out=$(run alice /usr/share/omarchy 1000 4); check "$out" "rc=3" "another user's session is not the pinned one"
printf 'UID=1000\nTYPE=wayland\nSTATE=closing\n' > "$tmp/sessions/4"
out=$(run alice /usr/share/omarchy 1000 4); check "$out" "rc=3" "a closing session is not live"
[[ $fails -eq 0 ]]
