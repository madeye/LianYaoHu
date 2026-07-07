pub mod env_policy;
pub mod helper;
pub mod interfaces;
pub mod pf;
pub mod route;
pub mod sandbox_profile;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

pub fn err(message: impl Into<String>) -> Error {
    message.into().into()
}
