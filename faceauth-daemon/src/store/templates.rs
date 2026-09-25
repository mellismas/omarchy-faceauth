//! What a user's template file holds: the embeddings with the camera each
//! was enrolled on, the gesture calibration, and the rules that prune a
//! set to its cap. A template matches only on its own camera, so a camera
//! swapped in finds nothing to match against.

#[cfg(test)]
use super::files::Store;
#[cfg(test)]
use super::seal::Sealing;
#[cfg(test)]
use super::test_support::{temp, tmpl, CAM};
use serde::{Deserialize, Serialize};

pub const FORMAT_VERSION: u32 = 1;

/// Templates per user. A sealed credential is capped at 1 MiB by systemd
/// (about 90 templates as compact JSON); the cap keeps every store the same
/// size, sealed or not. One walk-through writes up to 34, so the cap holds
/// a full walk-through with a few older looks, and Add Look prunes to it.
pub const MAX_TEMPLATES: usize = 40;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Template {
    /// L2-normalised embedding.
    pub embedding: Vec<f32>,
    /// Detector score of the frame it came from.
    pub quality: f32,
    /// Face width in pixels in the oriented frame, a proxy for distance.
    pub face_width: f32,
    /// Unix seconds.
    pub created: u64,
    /// Free text: "enrol", "glasses", ...
    pub label: String,
    /// The camera this was enrolled on (`IrCapture::identity`); a template
    /// only matches on that camera. Required: a file without it does not
    /// parse, so no template ever matches on every camera.
    pub device: String,
    /// The head pose the frame was taken at (`pose::Pose` yaw and
    /// nose_pitch), recorded with the template for a later look at which
    /// poses a set covers; nothing reads them yet. None on templates from
    /// before pose was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yaw: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nose_pitch: Option<f32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserTemplates {
    pub version: u32,
    pub user: String,
    /// The account's uid when enrolled. A recreated account with the same name
    /// is a different person; a mismatch on load is treated as not enrolled.
    /// Required: a file without it does not parse, so the check always runs.
    pub uid: u32,
    /// Which recognition model produced these; a model change invalidates them.
    pub model: String,
    pub templates: Vec<Template>,
    /// This person's gesture rounds, recorded in the enrolment walk-through.
    #[serde(default)]
    pub gesture: GestureCal,
}

/// What the enrolment walk-through recorded of this person's gestures, in
/// degrees from the face mesh. The consent window's floors derive from
/// where each gesture round stops reading (`floors_deg`); the swings are
/// kept for the record. A record written before round-4 C3 also carries
/// the image-motion fields of the removed fallback detectors (`nod`,
/// `shake`, `everyday`, `nod_floor_min`, `shake_floor_min`, `still_nod`,
/// `still_shake`): it parses, sets no floor from them, and drops them on
/// the next save.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct GestureCal {
    /// Each nod round's largest pitch swing and each shake round's
    /// largest yaw swing, and every everyday round's swing on both axes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nod_deg: Vec<f32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shake_deg: Vec<f32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub everyday_deg: Vec<EverydayDeg>,
    /// Where each recorded gesture round stops reading: the highest floor,
    /// degrees, at which the walk-through's replay of that round through
    /// the mesh detector still counted it as its gesture. The floors
    /// derive from these, not from the swings above: the detector's first
    /// leg runs from rest, about half the peak-to-peak swing, so a fraction
    /// of the swing said nothing about where the round stops reading.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nod_reads_to_deg: Vec<f32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shake_reads_to_deg: Vec<f32>,
}

/// An everyday round on the mesh: its largest 1.5 s swing in yaw and in
/// pitch, degrees.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct EverydayDeg {
    pub kind: String,
    pub dyaw: f32,
    pub dpitch: f32,
}

impl GestureCal {
    /// The margin under where a person's own gestures stop reading: the
    /// reference user's shake-1 stops at 21 degrees and a lighter shake at
    /// the card is more exposed than the one made for the walk-through.
    pub const MESH_FLOOR_MARGIN: f32 = 0.85;
    /// Caps on a derived mesh floor. The reference rounds (`traces/v2`)
    /// stop reading at 15 degrees for both nods and at 21 for the lighter
    /// shake; a person whose rounds all read far higher still gets a floor
    /// no ordinary gesture would miss.
    pub const NOD_DEG_MAX: f32 = 16.0;
    pub const SHAKE_DEG_MAX: f32 = 24.0;

    /// The mesh detectors' floors, degrees, derived by replay: the highest
    /// floor at which every one of this person's recorded gesture rounds
    /// still reads, times `MESH_FLOOR_MARGIN`, never under the detector's
    /// own minimum nor over the cap. Nothing recorded means the defaults.
    pub fn floors_deg(&self, default_nod: f32, default_shake: f32) -> (f32, f32) {
        let derive = |reads_to: &[f32], default: f32, cap: f32| {
            reads_to
                .iter()
                .copied()
                .fold(None, |m, x| Some(m.map_or(x, |m: f32| m.min(x))))
                .map(|r| (r * Self::MESH_FLOOR_MARGIN).clamp(default, cap))
                .unwrap_or(default)
        };
        (
            derive(&self.nod_reads_to_deg, default_nod, Self::NOD_DEG_MAX),
            derive(&self.shake_reads_to_deg, default_shake, Self::SHAKE_DEG_MAX),
        )
    }

    /// The walk-through recorded at least one nod round and one shake
    /// round that read on the mesh: the person has floors of their own.
    pub fn is_calibrated(&self) -> bool {
        !self.nod_reads_to_deg.is_empty() && !self.shake_reads_to_deg.is_empty()
    }
}

impl UserTemplates {
    /// An empty set for `user`, who is `uid` now; the caller resolves the
    /// account so an unknown name fails there, not as a set with no uid.
    pub fn new(user: &str, uid: u32, model: &str) -> Self {
        UserTemplates {
            version: FORMAT_VERSION,
            user: user.to_string(),
            uid,
            model: model.to_string(),
            templates: Vec::new(),
            gesture: GestureCal::default(),
        }
    }

    /// Best cosine similarity of `embedding` against every template, and which one.
    pub fn best_match(&self, embedding: &[f32]) -> Option<(f32, usize)> {
        self.templates
            .iter()
            .enumerate()
            .map(|(i, t)| (faceauth_engine::cosine(&t.embedding, embedding), i))
            .max_by(|a, b| a.0.total_cmp(&b.0))
    }

    /// As `best_match`, over the templates usable on camera `device`.
    pub fn best_match_on(&self, embedding: &[f32], device: &str) -> Option<(f32, usize)> {
        self.templates
            .iter()
            .enumerate()
            .filter(|(_, t)| t.usable_on(device))
            .map(|(i, t)| (faceauth_engine::cosine(&t.embedding, embedding), i))
            .max_by(|a, b| a.0.total_cmp(&b.0))
    }

    /// How many templates may match on camera `device`.
    pub fn usable_on(&self, device: &str) -> usize {
        self.templates
            .iter()
            .filter(|t| t.usable_on(device))
            .count()
    }

    /// The cameras the templates are bound to, for a message.
    pub fn bound_devices(&self) -> Vec<String> {
        let mut v: Vec<String> = self.templates.iter().map(|t| t.device.clone()).collect();
        v.sort();
        v.dedup();
        v
    }

    /// A template whose mean similarity to the rest of the set is under
    /// this is not a look of the same person: the reference set agrees at
    /// 0.90 pairwise, an impostor's frame scores 0.37 to 0.56 against it,
    /// and a garbage crop lower still.
    pub const OUTLIER_MEAN: f32 = 0.5;
    /// A template from a frame the detector scored under this is a poor
    /// crop (the daemon's own floor for a face is 0.6).
    pub const QUALITY_FLOOR: f32 = 0.6;

    /// Trim the set to `max` templates, one at a time, and return how many
    /// went. The order matters: a set pruned by nearest neighbour alone
    /// keeps whatever is least like the rest, so an impostor's frame or a
    /// garbage crop is the last thing to go and the person's own looks go
    /// first. So each round drops, in this order, a template inconsistent
    /// with the set (mean similarity to the others under `OUTLIER_MEAN`),
    /// then one of poor quality (under `QUALITY_FLOOR`), and only then the
    /// template most similar to another (the surplus copy of a look the set
    /// already has), so what remains covers the widest range of looks.
    pub fn prune_to(&mut self, max: usize) -> usize {
        let mut removed = 0;
        while self.templates.len() > max.max(1) {
            let n = self.templates.len();
            let sim = |i: usize, j: usize| {
                faceauth_engine::cosine(&self.templates[i].embedding, &self.templates[j].embedding)
            };
            let mean_to_rest = |i: usize| {
                (0..n).filter(|&j| j != i).map(|j| sim(i, j)).sum::<f32>() / (n - 1) as f32
            };
            let outlier = (0..n)
                .map(|i| (i, mean_to_rest(i)))
                .filter(|&(_, m)| m < Self::OUTLIER_MEAN)
                .min_by(|a, b| a.1.total_cmp(&b.1))
                .map(|(i, _)| i);
            let poor = || {
                (0..n)
                    .map(|i| (i, self.templates[i].quality))
                    .filter(|&(_, q)| {
                        !q.partial_cmp(&Self::QUALITY_FLOOR)
                            .is_some_and(|o| o.is_ge())
                    })
                    .min_by(|a, b| a.1.total_cmp(&b.1))
                    .map(|(i, _)| i)
            };
            let duplicate = || {
                (0..n)
                    .map(|i| {
                        let nearest = (0..n)
                            .filter(|&j| j != i)
                            .map(|j| sim(i, j))
                            .fold(-1.0, f32::max);
                        (i, nearest)
                    })
                    .max_by(|a, b| a.1.total_cmp(&b.1))
                    .map(|(i, _)| i)
                    .unwrap_or(0)
            };
            let victim = outlier.or_else(poor).unwrap_or_else(duplicate);
            self.templates.remove(victim);
            removed += 1;
        }
        removed
    }

    /// Pairwise similarity statistics of the stored templates: (min, mean, max).
    pub fn self_consistency(&self) -> Option<(f32, f32, f32)> {
        let n = self.templates.len();
        if n < 2 {
            return None;
        }
        let (mut lo, mut hi, mut sum, mut cnt) = (1f32, -1f32, 0f32, 0usize);
        for i in 0..n {
            for j in i + 1..n {
                let s = faceauth_engine::cosine(
                    &self.templates[i].embedding,
                    &self.templates[j].embedding,
                );
                lo = lo.min(s);
                hi = hi.max(s);
                sum += s;
                cnt += 1;
            }
        }
        Some((lo, sum / cnt as f32, hi))
    }
}

impl Template {
    fn usable_on(&self, device: &str) -> bool {
        self.device == device
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every template matches only on the camera it names: a set bound to
    /// one camera has nothing to match on another, whatever the score,
    /// and a set spanning two cameras matches each embedding only on its
    /// own (H4, H5).
    #[test]
    fn templates_match_only_on_their_camera() {
        let mut u = UserTemplates::new("alice", 1000, "glintr100");
        u.templates
            .push(tmpl(vec![1.0, 0.0], 1, "ipu3:ov7251 3-0060"));
        u.templates
            .push(tmpl(vec![0.0, 1.0], 2, "uvc:uvcvideo:1-1:1234:abcd"));
        assert_eq!(u.usable_on("ipu3:ov7251 3-0060"), 1);
        assert_eq!(u.usable_on("uvc:uvcvideo:1-1:1234:abcd"), 1);
        assert_eq!(u.usable_on("uvc:uvcvideo:Other Cam:usb-1"), 0);
        assert_eq!(
            u.best_match_on(&[1.0, 0.0], "ipu3:ov7251 3-0060").unwrap(),
            (1.0, 0)
        );
        assert_eq!(
            u.best_match_on(&[1.0, 0.0], "uvc:uvcvideo:1-1:1234:abcd")
                .unwrap(),
            (0.0, 1),
            "the other camera's template is the only candidate there"
        );
        assert!(
            u.best_match_on(&[1.0, 0.0], "uvc:uvcvideo:Other Cam:usb-1")
                .is_none(),
            "a camera no template names matches nothing"
        );
        assert_eq!(
            u.bound_devices(),
            vec![
                "ipu3:ov7251 3-0060".to_string(),
                "uvc:uvcvideo:1-1:1234:abcd".to_string()
            ]
        );
        let only_bound = UserTemplates {
            templates: vec![tmpl(vec![1.0, 0.0], 1, "ipu3:x")],
            ..u.clone()
        };
        assert_eq!(only_bound.usable_on("uvc:y"), 0);
        assert!(only_bound.best_match_on(&[1.0, 0.0], "uvc:y").is_none());
        assert_eq!(
            only_bound.best_match_on(&[1.0, 0.0], "ipu3:x").unwrap(),
            (1.0, 0)
        );
    }

    /// A file from before the camera and the uid were required (the
    /// development laptop's, or one edited to drop them) does not load:
    /// `load` fails naming re-enrolment, and nothing in it can match on
    /// any camera (H5). A file with both loads.
    #[test]
    fn a_file_without_device_or_uid_does_not_load() {
        let dir = temp("legacy");
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open_with(&dir, Sealing::Plain("test".into())).unwrap();
        let mut u = UserTemplates::new("alice", 1000, "glintr100");
        u.templates.push(tmpl(vec![1.0, 0.0], 1, CAM));
        let full = serde_json::to_string(&u).unwrap();
        let p = store.path_for("alice").unwrap();
        let without = |field: &str| -> String {
            let mut v: serde_json::Value = serde_json::from_str(&full).unwrap();
            match field {
                "uid" => {
                    v.as_object_mut().unwrap().remove("uid");
                }
                "device" => {
                    v["templates"][0].as_object_mut().unwrap().remove("device");
                }
                _ => unreachable!(),
            }
            serde_json::to_string(&v).unwrap()
        };
        for field in ["uid", "device"] {
            std::fs::write(&p, without(field)).unwrap();
            let err = match store.load("alice") {
                Err(e) => format!("{:#}", e),
                Ok(t) => panic!("a file without {} loaded: {:?}", field, t),
            };
            assert!(
                err.contains("re-enrol") && err.contains(field),
                "the error names the missing field and re-enrolment: {}",
                err
            );
        }
        std::fs::write(&p, &full).unwrap();
        let t = store.load("alice").unwrap().expect("a complete file loads");
        assert_eq!(t.uid, 1000);
        assert_eq!(t.best_match_on(&[1.0, 0.0], CAM).unwrap(), (1.0, 0));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A record from before round-4 C3 carries the image-motion fields of
    /// the fallback detectors: it still loads, sets no floor from them,
    /// and sheds them on the next save. Only the walk-through's replay
    /// results make a person calibrated, and they survive the store.
    #[test]
    fn a_record_with_the_image_motion_fields_still_loads_and_sets_no_floor() {
        let old: GestureCal = serde_json::from_str(
            r#"{"nod":[0.26,0.30],"shake":[0.33],"everyday":[{"kind":"read","dy":0.02,"dx":0.03}],"nod_floor_min":0.11,"shake_floor_min":0.05,"still_nod":[0.27],"still_shake":[0.5]}"#,
        )
        .unwrap();
        assert_eq!(old, GestureCal::default());
        assert!(!old.is_calibrated());
        assert_eq!(old.floors_deg(8.0, 15.0), (8.0, 15.0));
        let saved = serde_json::to_string(&old).unwrap();
        assert!(
            !saved.contains("nod_floor_min") && !saved.contains("still_nod"),
            "{}",
            saved
        );
        let cal = GestureCal {
            nod_deg: vec![34.7],
            shake_deg: vec![49.2],
            nod_reads_to_deg: vec![14.0],
            shake_reads_to_deg: vec![20.0],
            ..Default::default()
        };
        assert!(cal.is_calibrated());
        let dir = temp("cal");
        let store = Store::open_with(&dir, Sealing::Plain("test".into())).unwrap();
        let mut u = UserTemplates::new("alice", 1000, "glintr100");
        u.templates.push(tmpl(vec![1.0, 0.0], 1, CAM));
        u.gesture = cal.clone();
        store.save(&u).unwrap();
        assert_eq!(store.load("alice").unwrap().unwrap().gesture, cal);
        let _ = std::fs::remove_dir_all(dir);
    }

    fn unit(v: Vec<f32>) -> Vec<f32> {
        let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        v.iter().map(|x| x / n).collect()
    }

    /// Pruning drops the copies of a look the set already has and keeps
    /// the different ones. The looks here agree at 0.8 (a person with and
    /// without glasses, a turned head), as real looks of one face do.
    #[test]
    fn pruning_keeps_the_different_looks() {
        let mut u = UserTemplates::new("alice", 1000, "glintr100");
        let mk = |v: Vec<f32>, label: &str| Template {
            label: label.into(),
            ..tmpl(unit(v), 1, CAM)
        };
        u.templates.push(mk(vec![1.0, 0.0, 0.0], "a"));
        u.templates.push(mk(vec![1.0, 0.05, 0.0], "a-copy"));
        u.templates.push(mk(vec![1.0, -0.05, 0.0], "a-copy"));
        u.templates.push(mk(vec![0.8, 0.6, 0.0], "b"));
        u.templates.push(mk(vec![0.8, 0.0, 0.6], "c"));
        assert_eq!(u.prune_to(3), 2);
        let mut kept: Vec<&str> = u.templates.iter().map(|t| t.label.as_str()).collect();
        kept.sort();
        assert_eq!(
            kept,
            vec!["a", "b", "c"],
            "one of each look survives; the near copies go"
        );
        assert_eq!(u.prune_to(10), 0);
    }

    /// An impostor's frame and a garbage crop have no close neighbour, so a
    /// nearest-neighbour prune kept them and dropped the person's own looks.
    /// They go first now: the outlier, then the poor crop, then duplicates.
    #[test]
    fn pruning_drops_the_impostor_and_the_junk_before_the_person() {
        let mut u = UserTemplates::new("alice", 1000, "glintr100");
        let genuine = |v: Vec<f32>, label: &str| Template {
            label: label.into(),
            ..tmpl(unit(v), 1, CAM)
        };
        u.templates
            .push(genuine(vec![1.0, 0.0, 0.0, 0.0], "look-1"));
        u.templates
            .push(genuine(vec![1.0, 0.1, 0.0, 0.0], "look-1b"));
        u.templates
            .push(genuine(vec![0.9, 0.4, 0.0, 0.0], "look-2"));
        u.templates
            .push(genuine(vec![0.9, 0.0, 0.4, 0.0], "look-3"));
        u.templates.push(Template {
            label: "impostor".into(),
            ..tmpl(unit(vec![0.0, 0.0, 0.0, 1.0]), 1, CAM)
        });
        u.templates.push(Template {
            label: "junk".into(),
            quality: 0.31,
            ..tmpl(unit(vec![0.95, 0.3, 0.0, 0.0]), 1, CAM)
        });
        assert_eq!(u.prune_to(5), 1);
        assert!(
            u.templates.iter().all(|t| t.label != "impostor"),
            "the outlier goes first"
        );
        assert_eq!(u.prune_to(4), 1);
        assert!(
            u.templates.iter().all(|t| t.label != "junk"),
            "then the poor crop"
        );
        assert_eq!(u.prune_to(3), 1);
        let mut kept: Vec<&str> = u.templates.iter().map(|t| t.label.as_str()).collect();
        kept.sort();
        assert_eq!(kept, vec!["look-1", "look-2", "look-3"], "then a near copy");
    }

    /// The mesh floors sit a margin under the lowest point at which any of
    /// the person's recorded rounds stops reading, never under the
    /// detector's minimum nor over the cap; the swings play no part.
    #[test]
    fn mesh_floors_sit_under_where_the_recorded_rounds_stop_reading() {
        let mut g = GestureCal::default();
        assert_eq!(
            g.floors_deg(8.0, 15.0),
            (8.0, 15.0),
            "nothing recorded: the defaults"
        );
        // The reference user's swings alone (the old input) change nothing.
        g.nod_deg = vec![34.7, 25.7];
        g.shake_deg = vec![49.2, 56.8];
        assert_eq!(g.floors_deg(8.0, 15.0), (8.0, 15.0));
        // The reference rounds: both nods read up to 14 degrees, the shakes
        // to 20 and past 26 (2026-09-24 replay).
        g.nod_reads_to_deg = vec![14.0, 14.0];
        g.shake_reads_to_deg = vec![26.0, 20.0];
        let (n, s) = g.floors_deg(8.0, 15.0);
        assert!(
            (n - 11.9).abs() < 0.01 && (s - 17.0).abs() < 0.01,
            "0.85 of the lowest drop-out: {} {}",
            n,
            s
        );
        // A round that reads only at the minimum keeps the floor there.
        g.nod_reads_to_deg = vec![14.0, 8.0];
        assert_eq!(g.floors_deg(8.0, 15.0).0, 8.0);
        g.nod_reads_to_deg = vec![80.0];
        g.shake_reads_to_deg = vec![120.0];
        assert_eq!(
            g.floors_deg(8.0, 15.0),
            (GestureCal::NOD_DEG_MAX, GestureCal::SHAKE_DEG_MAX),
            "capped so a light gesture still counts"
        );
    }
}
