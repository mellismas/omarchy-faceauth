#!/bin/sh
# Whole-system draw from the battery meter (unplugged) across daemon states.
# Run as root: pkexec sh tools/power-measure.sh
# Each phase samples every 5 s for 60 s and prints the mean draw in mW,
# the CPU package mean from RAPL, and the share of time in the deepest C-state.
set -u
CFG=/etc/faceauth/config.toml
R=/sys/class/powercap/intel-rapl:0/energy_uj
C10=/sys/devices/system/cpu/cpu0/cpuidle/state8/time
draw() { t=0; for b in /sys/class/power_supply/BAT*; do [ "$(cat $b/status)" = Discharging ] && t=$((t + $(cat $b/power_now))); done; echo $t; }
phase() {
  sleep 8   # let the change settle
  n=0; sum=0; e0=$(cat $R); c0=$(cat $C10); t0=$(date +%s%N)
  while [ $n -lt 12 ]; do sleep 5; sum=$((sum + $(draw))); n=$((n + 1)); done
  e1=$(cat $R); c1=$(cat $C10); t1=$(date +%s%N)
  us=$(( (t1 - t0) / 1000 ))
  echo "$1: draw $((sum / n / 1000)) mW, package $(( (e1 - e0) / (us / 1000) )) mW, C10 $(( (c1 - c0) * 100 / us ))%"
}
for b in /sys/class/power_supply/BAT*; do echo "$b $(cat $b/status)"; done
cp $CFG $CFG.power-measure.bak
phase "presence on, battery tick 5s (as shipped)"
sed -i '/^\[presence\]/a battery_tick_seconds = 2.0' $CFG; systemctl restart faceauth
phase "presence on, battery tick 2s"
cp $CFG.power-measure.bak $CFG; sed -i 's/^enabled = true/enabled = false/' $CFG; systemctl restart faceauth
phase "daemon on, presence off"
systemctl stop faceauth
phase "daemon stopped"
cp $CFG.power-measure.bak $CFG; rm $CFG.power-measure.bak; systemctl start faceauth
sleep 2; echo "restored: $(systemctl is-active faceauth)"
