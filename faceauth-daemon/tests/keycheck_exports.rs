//! Round 19: the key check's libfido2 wrapper (`keycheck_cancel.rs`) works
//! only while both ends hold: the helper exports `fido_dev_get_assert`, so
//! the dynamic linker binds pam_u2f's call there before libfido2's, and
//! pam_u2f takes that call from outside itself.

use faceauth_daemon::elfsym::{dynamic_symbol_of, Sym};
use std::path::Path;

#[test]
fn the_key_helper_exports_the_wrapper_pam_u2f_calls() {
    let helper = Path::new(env!("CARGO_BIN_EXE_faceauth-keycheck"));
    assert_eq!(
        dynamic_symbol_of(helper, "fido_dev_get_assert"),
        Some(Sym::Exported),
        "the helper does not export the wrapper"
    );
    let pam_u2f = Path::new("/usr/lib/security/pam_u2f.so");
    if pam_u2f.exists() {
        assert_eq!(
            dynamic_symbol_of(pam_u2f, "fido_dev_get_assert"),
            Some(Sym::Imported),
            "pam_u2f no longer asks the key through fido_dev_get_assert"
        );
    }
}
