# Print recordings

Recorded from the camera, unlike `../redteam/`, which is synthetic. Not
part of the calibration corpus.

- `2026-09-22-print-waggle-handheld.txt`: the reference user's face matched,
  then a paper print of it was held over the face at roughly face distance
  and moved up and down by hand. The recording holds the first 43 s (the
  buffer's 1200 looked-at frames). The print's box swings about two face
  widths and its width changes by half: far larger than a nod, and every leg
  is thrown out by the detector's size ceiling and box-width tolerance. A
  print moved at nod scale (ten to twenty pixels) is the case the strobed
  confirm exists for and is not recorded yet.
