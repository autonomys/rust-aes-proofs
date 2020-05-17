/// Proof of replication implementation
#[cfg(target_arch = "x86_64")]
pub mod aes_ni;
pub mod opencl;
pub mod software;
#[cfg(test)]
mod test_data;

pub const BLOCK_SIZE: usize = 16;
pub const PIECE_SIZE: usize = 4096;

pub type Block = [u8; BLOCK_SIZE];
pub type Piece = [u8; PIECE_SIZE];
