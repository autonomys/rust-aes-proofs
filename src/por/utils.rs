use crate::por::Block;
use crate::por::Piece;
use crate::por::BLOCK_SIZE;
use std::convert::TryInto;

/// Returns (blocks, feedback) tuple given block index in a piece
pub fn piece_to_blocks_and_feedback(
    piece: &mut Piece,
    index: usize,
    number_of_blocks: usize,
) -> (&mut [u8], &Block) {
    let (ends_with_feedback, starts_with_block) =
        piece.split_at_mut(index * BLOCK_SIZE * number_of_blocks);

    let feedback = ends_with_feedback[ends_with_feedback.len() - BLOCK_SIZE..]
        .as_ref()
        .try_into()
        .unwrap();

    let (blocks, _) = starts_with_block.split_at_mut(BLOCK_SIZE * number_of_blocks);

    (blocks, feedback)
}

/// Returns (blocks, feedback) tuple given piece and optional feedback
pub fn piece_to_first_blocks_and_feedback<'a>(
    piece: &'a mut Piece,
    feedback: Option<&'a Block>,
    number_of_blocks: usize,
) -> (&'a mut [u8], &'a Block) {
    let (first_blocks, remainder) = piece.split_at_mut(BLOCK_SIZE * number_of_blocks);
    // At this point last block is already decoded, so we can use it as an IV to previous iteration
    let iv = feedback.unwrap_or_else(move || {
        remainder[(remainder.len() - BLOCK_SIZE)..]
            .try_into()
            .unwrap()
    });

    (first_blocks, iv)
}
