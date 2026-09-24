#!/bin/bash
# Record a gesture calibration battery: twenty labelled consent windows with
# the daemon recording every frame and deciding nothing, then the recordings
# copied here under their item names. Needs root twice (turning recording on,
# restoring the config); the windows themselves grant nothing.
#
# The root steps take every path as a positional argument rather than
# splicing it into the script text, so a directory name with a quote or a
# space cannot change what runs as root. Root never writes into a directory
# this user owns: the recordings are copied into a root-owned temporary
# directory, handed over with chown, and moved into place by the user.
#
#   tools/battery.sh [USER] [OUTDIR]      default: $USER, faceauth-daemon/traces/cal-$(date +%Y%m%d)
#
# For each window: once it says "Recognised", do what the label says; otherwise stay as you are.
set -u
user=${1:-$USER}
out=${2:-"$(dirname "$0")/../faceauth-daemon/traces/cal-$(date +%Y%m%d)"}
cfg=/etc/faceauth/config.toml
items=(
 "still:Stay still, look at the camera"
 "still:Stay still, look at the camera"
 "nod:Nod twice, naturally"
 "nod:Nod twice, naturally"
 "nod:Nod twice, naturally"
 "nod-slow:Nod twice, slow and deliberate"
 "nod-light:Nod twice, small and light"
 "shake:Shake twice, naturally"
 "shake:Shake twice, naturally"
 "shake:Shake twice, naturally"
 "shake-slow:Shake twice, slowly"
 "glance:Glance at the other monitor and back"
 "glance:Glance at the other monitor and back"
 "look-down:Look down at the keyboard, then back up"
 "look-down:Look down at the keyboard, then back up"
 "read:Read the screen the whole time"
 "lean:Lean in toward the screen and back"
 "talk:Say a sentence to the camera"
 "nod-single:One single nod only"
 "shake-single:One single shake only"
)
mkdir -p "$out"
slugs=$(mktemp); for it in "${items[@]}"; do echo "${it%%:*}" >> "$slugs"; done
# The keys go above the first table, or they would land inside it and be ignored.
pkexec sh -c '
  echo "FACEAUTH BATTERY: turn on recording (record-only) and restart"
  set -e
  cfg=$1
  cp "$cfg" "$cfg.pre-battery"
  sed -i "/^gesture_trace *=/d; /^gesture_record_only *=/d" "$cfg"
  sed -i "0,/^\\[/s//gesture_trace = true\\ngesture_record_only = true\\n\\n[/" "$cfg"
  grep -q "^gesture_trace = true" "$cfg"
  systemctl restart faceauth.service
  sleep 5
  systemctl is-active faceauth.service
' sh "$cfg" || exit 1
sleep 4
start=$(date +%s)
n=0; total=${#items[@]}
for it in "${items[@]}"; do
  n=$((n+1)); text=${it#*:}
  timeout 14 faceauth auth --user "$user" --consent "FACEAUTH CAL $n/$total: $text" > /dev/null 2>&1
  echo "$n ${it%%:*} recorded"
  sleep 2
done
# Root copies into a directory only root can reach, then hands it over; the
# user does the move. Root never follows a path into a user-owned directory.
staging=$(pkexec sh -c '
  echo "FACEAUTH BATTERY: restore the config and collect the recordings" >&2
  set -e
  cfg=$1; start=$2; slugs=$3; user=$4
  mv "$cfg.pre-battery" "$cfg"
  systemctl restart faceauth.service
  staging=$(mktemp -d /tmp/faceauth-battery.XXXXXX)
  cd /var/lib/faceauth/gestures
  i=0
  for f in $(ls -1 | awk -F- -v s="$start" "\$1 >= s" | sort); do
    i=$((i+1))
    slug=$(sed -n "${i}p" "$slugs")
    [ -z "$slug" ] && slug=extra
    cp "$f" "$staging/$(printf %02d "$i")-$slug.txt"
  done
  chown -R "$user" "$staging"
  echo "$staging"
' sh "$cfg" "$start" "$slugs" "$user") || exit 1
mv "$staging"/* "$out"/ && rmdir "$staging"
rm -f "$slugs"
ls "$out" | wc -l
echo "recordings in $out; replay them with: cargo test --release -p faceauth-daemon cal_report -- --ignored --nocapture"
