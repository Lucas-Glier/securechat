pub mod framing;
pub mod noise_lab;
pub mod tcp_handshake;

pub type DynError = Box<dyn std::error::Error + Send + Sync>;
