// The key helper's libfido2 wrapper (round 19, src/keycheck_cancel.rs)
// works only if the dynamic linker can bind pam_u2f's call to it, which
// needs the name in the helper's dynamic symbol table; an executable puts
// only what it is told to there. tests/keycheck_exports.rs holds it.
fn main() {
    println!(
        "cargo:rustc-link-arg-bin=faceauth-keycheck=-Wl,--export-dynamic-symbol=fido_dev_get_assert"
    );
}
