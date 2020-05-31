/// Proof of replication implementations

#[cfg(target_arch = "x86_64")]
pub mod aes_ni;
pub mod opencl;
pub mod software_bit_slicing;
pub mod software_lut;
#[cfg(test)]
mod test_data;
mod utils;
#[cfg(target_arch = "x86_64")]
pub mod vaes;
