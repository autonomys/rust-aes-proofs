#[cfg(target_arch = "x86_64")]
pub mod aes_ni;
pub mod key_expansion;
#[cfg(target_arch = "x86_64")]
pub mod vaes;
