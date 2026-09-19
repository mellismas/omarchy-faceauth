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
    let auth = Authenticator::new(cfg)?;
    log::info!("models loaded; ready");
    server::serve(auth, &socket)
}
