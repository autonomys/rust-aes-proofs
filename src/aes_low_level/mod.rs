#[cfg(target_arch = "x86_64")]
pub mod aes_ni;
#[cfg(feature = "opencl")]
pub mod software;
#[cfg(target_arch = "x86_64")]
pub mod vaes;
