//! `faceauthd`: the system service. Started at boot as a plain `Type=simple`
//! unit, never socket- or D-Bus-activated: an on-demand start would go
//! through polkit into a PAM stack that contains `pam_faceauth`, which
//! would then wait on the daemon being started. Owns the cameras and the
//! templates; answers the PAM module.

use anyhow::Result;
use faceauth_daemon::{auth::Authenticator, config::Config, server};

fn main() -> Result<()> {
    // No timestamp of our own: journald stamps every line in local time.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .init();
    let cfg_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/faceauth/config.toml".into());
    let cfg = Config::load(&cfg_path)?;
    log::info!(
        "config {}: models {} store {} socket {}",
        cfg_path,
        cfg.models_dir.display(),
        faceauth_daemon::config::STORE_DIR,
        faceauth_daemon::config::SOCKET
    );
    let socket = std::path::PathBuf::from(faceauth_daemon::config::SOCKET);
    let presence = cfg.presence.clone();
    let authenticator = Authenticator::new(cfg)?;
    let auth = std::sync::Arc::new(std::sync::Mutex::new(authenticator));
    log::info!("models loaded; ready");
    if presence.enabled {
        let a = std::sync::Arc::clone(&auth);
        std::thread::Builder::new()
            .name("presence".into())
            .spawn(move || faceauth_daemon::presence::run(a, presence))?;
    }
    server::serve(auth, &socket)
}
