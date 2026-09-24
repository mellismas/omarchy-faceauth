# Round recordings, format v2 (mesh angles)

Recorded 2026-09-24 through the enrolment walk-through's rounds on the
reference machine: one file per round, a header line, then one line per
frame: `t yaw pitch roll pos_x pos_y w cx cy size score`. Angles in degrees
from the face mesh (yaw negative turned to the subject's left as this camera
sees it, pitch positive chin down, roll positive left eye lower); pos_x and
pos_y the accumulated image motion of the face in face widths, which nothing
reads since the image-motion detectors went (round-4 C3); w, cx, cy the
detector box; size the face width as a fraction of the frame's shorter
side; score the mesh's face confidence. Numbers only, never an image.

Recordings made since then carry the header `v3 t yaw pitch roll w cx cy
size score`, the same columns without the two image-motion ones. The
walk-through's rounds and the consent window write it alike
(`consent::ROUND_HEADER`), and `consent::parse_round` reads either header,
so a recording from a live request replays through the same tests as these
rounds. These twelve files are the mesh battery (`mesh_battery_holds`) and
the source of the derived-floor test and the red-team module's turned-head
case; they are the only recorded corpus left.

What they showed, and what the mesh-based detectors are built on:

| round | legs | size (deg) | leg time (s) | dwell at the end (s) |
| --- | --- | --- | --- | --- |
| nod (x2) | 4 to 5 pitch legs | 12 to 35 | 0.23 to 0.33 | 0.06 to 0.14 |
| shake (x2) | 3 to 4 yaw legs | 33 to 53 | 0.30 to 0.33 | 0.03 to 0.26 |
| glance right/left (x4) | 3 to 4 yaw legs | 32 to 50 | 0.34 to 2.2 | 0.33 to 1.23 |
| keyboard | 4 pitch legs | 17 to 21 | 0.9 to 2.0 | 0.46 to 0.70 |
| read | slow yaw and pitch | 16 to 27 | 1.6 to 4.0 | 1.7 to 2.3 |
| talk | none over 6 | 4 | | |
| lean | 3 pitch legs | 18 to 30 | 1.1 to 3.3 | 0.7 to 1.1 |

Size does not separate a glance from a shake or a keyboard look from a nod:
the everyday movements are as large as the gestures. Timing does: a gesture
leg takes about a third of a second and reverses at once; an everyday
movement takes a second or more and holds at its end.
