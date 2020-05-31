/// Proof of time implementation
#[cfg(target_arch = "x86_64")]
pub mod aes_ni;
#[cfg(test)]
mod test_data;
#[cfg(target_arch = "x86_64")]
pub mod vaes;

const MIN_VERIFIER_PARALLELISM: usize = 4;
const MAX_VERIFIER_PARALLELISM: usize = 16;
