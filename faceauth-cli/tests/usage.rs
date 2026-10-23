//! The built `faceauth` asked for help, and given words that name no
//! command. Neither reaches the daemon.

use std::process::Command;

/// I8: help asked for is an answer, on stdout with exit 0; words that name
/// no command are an error, the usage on stderr with exit 2.
#[test]
fn help_goes_to_stdout_with_exit_0_and_a_wrong_word_to_stderr_with_exit_2() {
    let bin = env!("CARGO_BIN_EXE_faceauth");
    for help in [&["--help"][..], &["-h"], &["help"], &["enroll", "--help"]] {
        let out = Command::new(bin).args(help).output().unwrap();
        assert_eq!(out.status.code(), Some(0), "{:?}", help);
        let text = String::from_utf8(out.stdout).unwrap();
        assert!(
            text.starts_with("usage:\n") && text.contains("  faceauth doctor"),
            "{:?}: {}",
            help,
            text
        );
        assert!(out.stderr.is_empty(), "{:?}", help);
    }
    for wrong in [&[][..], &["no-such-command"]] {
        let out = Command::new(bin).args(wrong).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{:?}", wrong);
        assert!(out.stdout.is_empty(), "{:?}", wrong);
        assert!(
            String::from_utf8_lossy(&out.stderr).starts_with("usage:\n"),
            "{:?}",
            wrong
        );
    }
}

/// A flag's value is never help: `--label -h` names the look `-h`, so the
/// enrollment is asked for (here of a socket that is not there) and fails,
/// where it used to print the usage and exit 0 with nothing enrolled.
#[test]
fn help_as_a_flags_value_is_the_value() {
    let bin = env!("CARGO_BIN_EXE_faceauth");
    let out = Command::new(bin)
        .args([
            "enroll",
            "--socket",
            "/nonexistent/faceauth.sock",
            "--user",
            "nobody",
            "--label",
            "-h",
            "--guided",
            "--start",
            "distance",
        ])
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("usage:"), "{}", stdout);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("/nonexistent/faceauth.sock"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
