#!/bin/bash
# Record a gesture calibration battery: twenty labelled consent windows with
# the daemon recording every frame and deciding nothing, then the recordings
# copied here under their item names. Needs root twice (turning recording on,
# restoring the config); the windows themselves grant nothing.
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
pkexec sh -c "echo 'FACEAUTH BATTERY: turn on recording (record-only) and restart'; set -e; cp $cfg $cfg.pre-battery; sed -i '/^gesture_trace *=/d; /^gesture_record_only *=/d' $cfg; sed -i '0,/^\\[/s//gesture_trace = true\\ngesture_record_only = true\\n\\n[/' $cfg; grep -q '^gesture_trace = true' $cfg; systemctl restart faceauth.service; sleep 5; systemctl is-active faceauth.service" || exit 1
sleep 4
start=$(date +%s)
n=0; total=${#items[@]}
for it in "${items[@]}"; do
  n=$((n+1)); text=${it#*:}
  timeout 14 faceauth auth --user "$user" --consent "FACEAUTH CAL $n/$total: $text" > /dev/null 2>&1
  echo "$n ${it%%:*} recorded"
  sleep 2
done
pkexec sh -c "echo 'FACEAUTH BATTERY: restore the config and collect the recordings'; set -e; mv $cfg.pre-battery $cfg; systemctl restart faceauth.service; cd /var/lib/faceauth/gestures; i=0; for f in \$(ls -1 | awk -F- '\$1 >= $start' | sort); do i=\$((i+1)); slug=\$(sed -n \"\${i}p\" $slugs); [ -z \"\$slug\" ] && slug=extra; cp \"\$f\" \"$out/\$(printf %02d \$i)-\$slug.txt\"; done; chown -R $user \"$out\"; ls \"$out\" | wc -l"
rm -f "$slugs"
echo "recordings in $out; replay them with: cargo test --release -p faceauth-daemon cal_report -- --ignored --nocapture"
