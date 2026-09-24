#!/bin/bash
# The built PAM module links libpam (so a host that loads libpam privately
# can still resolve pam_get_user), imports nothing that would let it set a
# password item, and exports the three entry points and nothing else.
#
#   tests/pam-module-test.sh [path/to/libpam_faceauth.so]
#
# Without an argument the module is looked for under CARGO_TARGET_DIR, then
# the workspace's target/, release first.
set -uo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
so=${1:-}
if [[ -z $so ]]; then
  for dir in "${CARGO_TARGET_DIR:-}" "$here/../target"; do
    [[ -n $dir ]] || continue
    for profile in release debug; do
      if [[ -f $dir/$profile/libpam_faceauth.so ]]; then so=$dir/$profile/libpam_faceauth.so; break 2; fi
    done
  done
fi
[[ -f ${so:-} ]] || { echo "not ok - no libpam_faceauth.so found (build it, or pass the path)"; exit 1; }
fails=0
check() { if [[ $1 == "$2" ]]; then echo "ok - $3"; else echo "not ok - $3 (got '$1', want '$2')"; fails=$((fails+1)); fi; }

needed=$(readelf -d "$so" | grep -c 'NEEDED.*libpam\.so\.0')
check "$needed" "1" "the module has DT_NEEDED on libpam.so.0"
imports=$(nm -D --undefined-only "$so" | awk '{print $2}' | sed 's/@.*//' | grep '^pam_' | sort | tr '\n' ' ')
check "$imports" "pam_get_item pam_get_user pam_syslog " "the module imports only pam_get_item, pam_get_user and pam_syslog"
exports=$(nm -D --defined-only "$so" | awk '{print $3}' | grep '^pam_' | sort | tr '\n' ' ')
check "$exports" "pam_sm_acct_mgmt pam_sm_authenticate pam_sm_setcred " "the module exports the three entry points only"
[[ $fails -eq 0 ]]
