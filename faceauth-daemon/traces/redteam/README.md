# Red-team traces, 2026-09-22

SYNTHETIC. These were written by hand for the C1 finding in
`../security-review-20260922-redteam.html`; they were not recorded from a camera.
Do not fold them into `src/faceauth-daemon/traces/cal/`, which is a recorded corpus.

Same 19-field layout as a live trace
(`t/pitch/yaw/width/cx/cy` + five landmark pairs + score + `pos_x` + `pos_y`),
106 frames each at about 28 fps.

- `waggled-board.txt` — landmarks and box translate vertically together by 0.14
  face widths, two waggles. Stands for a rigid object moved by hand.
- `frozen-box.txt` — the stricter case. Box width, centre, landmarks and yaw are
  a single value for all 106 frames (`92/252/342`); only `pos_y` oscillates,
  0.000 to 0.070, just above the 0.06 floor.

Both produce a NOD from the shipped detector, replayed through the `cal_dump`
test with `FACEAUTH_FLICKER=none`. Keep them as regression cases for any fix to
the gesture phase: a patched detector should refuse both.
