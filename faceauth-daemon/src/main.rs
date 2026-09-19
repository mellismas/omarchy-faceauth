//! `faceauthd`: the system service. Started at boot as a plain `Type=simple`
//! unit, never socket- or D-Bus-activated (see the PAM recursion trap in the
//! design). Owns the cameras and the templates; answers the PAM module.

use anyhow::Result;
use faceauth_daemon::{auth::Authenticator, config::Config, server};

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).format_timestamp_millis().init();
    let cfg_path = std::env::args().nth(1).unwrap_or_else(|| "/etc/faceauth/config.toml".into());
    let cfg = Config::load(&cfg_path)?;
    log::info!("config {}: models {} store {} socket {}", cfg_path, cfg.models_dir.display(), cfg.store_dir.display(), cfg.socket.display());
    let socket = cfg.socket.clone();
    let presence = cfg.presence.clone();
    let mut authenticator = Authenticator::new(cfg)?;
    server::attach(&mut authenticator);
    let auth = std::sync::Arc::new(std::sync::Mutex::new(authenticator));
    log::info!("models loaded; ready");
    if presence.enabled {
        let a = std::sync::Arc::clone(&auth);
        std::thread::Builder::new().name("presence".into()).spawn(move || faceauth_daemon::presence::run(a, presence))?;
    }
    server::serve(auth, &socket)
}
