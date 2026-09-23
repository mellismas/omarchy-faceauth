# Print recordings

Recorded from the camera, unlike `../redteam/`, which is synthetic. Not
part of the calibration corpus.

- `2026-09-22-print-waggle-handheld.txt`: the reference user's face matched,
  then a paper print of it was held over the face at roughly face distance
  and moved up and down by hand. The recording holds the first 43 s (the
  buffer's 1200 looked-at frames). The box width jumps between about 85 and
  160 px and the centre leaps 200 px within a few frames: the detector was
  most likely alternating between the paper and the user's own face showing
  around its edge, not following one moving object. So this is a record of
  "paper in play, no nod counted", not a clean print-only waggle. Every leg
  was thrown out by the size ceiling and the box-width tolerance. A print
  alone, moved at nod scale (ten to twenty pixels), is the case the strobed
  confirm exists for and is not recorded yet.
