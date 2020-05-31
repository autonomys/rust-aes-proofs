pub mod aes_low_level;
pub mod por;
pub mod pot;
pub mod utils;

pub const BLOCK_SIZE: usize = 16;
pub const PIECE_SIZE: usize = 4096;

pub type Block = [u8; BLOCK_SIZE];
pub type Piece = [u8; PIECE_SIZE];
