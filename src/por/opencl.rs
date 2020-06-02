mod utils;

use crate::aes_low_level::software;
use crate::Block;
use crate::BLOCK_SIZE;
use crate::PIECE_SIZE;
use ocl::{
    core::{
        build_program, create_buffer, create_command_queue, create_context, create_kernel,
        create_program_with_source, enqueue_kernel, enqueue_read_buffer, enqueue_write_buffer,
        finish, set_kernel_arg, ArgVal, CommandQueue, Context, ContextProperties, Event, Kernel,
        Mem, Uchar16, Uint,
    },
    flags, Device, MemFlags, OclPrm, Platform, Result,
};
use std::ffi::CString;

const AES_OPEN_CL: &str = include_str!("opencl/kernels.cl");
const ROUND_KEYS_LENGTH_128: usize = 44;

struct CachedBuffer {
    mem: Mem,
    buffer_size: usize,
}

pub struct OpenCLKeys {
    keys_enc: [Block; 11],
    keys_dec: [Block; 11],
}

impl OpenCLKeys {
    pub fn new(id: &Block) -> Self {
        let keys_enc = software::expand_keys_aes_128_enc(&id);
        let keys_dec = software::expand_keys_aes_128_dec(&id);
        Self { keys_enc, keys_dec }
    }
}

pub struct OpenCL {
    buffer_state: Option<CachedBuffer>,
    buffer_iv: Option<CachedBuffer>,
    buffer_round_keys: Mem,
    context: Context,
    por_128_enc_kernel: Kernel,
    por_128_dec_kernel: Kernel,
    queue: CommandQueue,
}

impl OpenCL {
    pub fn new() -> Result<Self> {
        let platform = Platform::first()?;

        let device = Device::first(platform)?;

        let context_properties = ContextProperties::new().platform(platform);
        let context = create_context(Some(&context_properties), &[&device], None, None)?;

        let queue = create_command_queue(&context, &device, None)?;

        let program = create_program_with_source(&context, &[CString::new(AES_OPEN_CL)?])?;

        let options = CString::new("").unwrap();
        build_program(&program, Some(&[&device]), &options, None, None)?;

        let por_128_enc_kernel = create_kernel(&program, "por_128_enc")?;
        let por_128_dec_kernel = create_kernel(&program, "por_128_dec")?;

        let buffer_round_keys = unsafe {
            create_buffer(
                &context,
                flags::MEM_READ_ONLY | flags::MEM_ALLOC_HOST_PTR,
                ROUND_KEYS_LENGTH_128,
                None::<&[Uint]>,
            )?
        };

        set_kernel_arg(&por_128_enc_kernel, 2, ArgVal::mem(&buffer_round_keys))?;
        set_kernel_arg(&por_128_dec_kernel, 2, ArgVal::mem(&buffer_round_keys))?;

        let buffer_state = Default::default();
        let buffer_iv = Default::default();
        Ok(Self {
            buffer_state,
            buffer_iv,
            buffer_round_keys,
            context,
            por_128_enc_kernel,
            por_128_dec_kernel,
            queue,
        })
    }

    /// Takes plaintext input that is multiple of piece size (4096 bytes), same number of IVs and
    /// expanded round keys
    ///
    /// Produces ciphertext
    pub fn encode(
        &mut self,
        input: &[u8],
        ivs: &[Block],
        keys: &OpenCLKeys,
        aes_iterations: u32,
        breadth_iterations: u32,
    ) -> Result<Vec<u8>> {
        assert!(input.len() % PIECE_SIZE == 0);

        let blocks_count = input.len() / PIECE_SIZE;
        assert!(blocks_count == ivs.len());

        let buffer_state = Self::validate_or_allocate_buffer::<Uchar16>(
            &self.context,
            &mut self.buffer_state,
            input.len(),
            flags::MEM_READ_WRITE | flags::MEM_ALLOC_HOST_PTR,
        )?;

        let buffer_ivs = Self::validate_or_allocate_buffer::<Uchar16>(
            &self.context,
            &mut self.buffer_iv,
            ivs.len(),
            flags::MEM_READ_WRITE | flags::MEM_ALLOC_HOST_PTR,
        )?;

        set_kernel_arg(&self.por_128_enc_kernel, 0, ArgVal::mem(&buffer_state))?;
        set_kernel_arg(&self.por_128_enc_kernel, 1, ArgVal::mem(&buffer_ivs))?;
        set_kernel_arg(&self.por_128_enc_kernel, 3, ArgVal::scalar(&aes_iterations))?;
        set_kernel_arg(
            &self.por_128_enc_kernel,
            4,
            ArgVal::scalar(&breadth_iterations),
        )?;

        unsafe {
            enqueue_write_buffer(
                &self.queue,
                &buffer_state,
                true,
                0,
                &utils::inputs_to_uchar16_vec(input),
                None::<Event>,
                None::<&mut Event>,
            )?;
        }

        unsafe {
            enqueue_write_buffer(
                &self.queue,
                &buffer_ivs,
                true,
                0,
                &utils::ivs_to_uchar16_vec(&ivs),
                None::<Event>,
                None::<&mut Event>,
            )?;
        }

        unsafe {
            enqueue_write_buffer(
                &self.queue,
                &self.buffer_round_keys,
                true,
                0,
                &utils::keys_to_uint_vec(&keys.keys_enc),
                None::<Event>,
                None::<&mut Event>,
            )?;
        }

        unsafe {
            enqueue_kernel(
                &self.queue,
                &self.por_128_enc_kernel,
                1,
                None,
                // TODO: This will not handle too big inputs that exceed VRAM
                &[blocks_count, 0, 0],
                None,
                None::<Event>,
                None::<&mut Event>,
            )
        }?;

        let mut output = Vec::<u8>::with_capacity(input.len());
        {
            let mut result = Uchar16::from([0u8; BLOCK_SIZE]);
            for offset in (0..input.len()).step_by(BLOCK_SIZE) {
                unsafe {
                    enqueue_read_buffer(
                        &self.queue,
                        &buffer_state,
                        true,
                        offset,
                        &mut result,
                        None::<Event>,
                        None::<&mut Event>,
                    )?;
                }
                output.extend_from_slice(&result);
            }
        }

        finish(&self.queue)?;

        Ok(output)
    }

    /// Takes ciphertext input that is multiple of piece size (4096 bytes), same number of IVs and
    /// expanded round keys
    ///
    /// Produces plaintext
    pub fn decode(
        &mut self,
        input: &[u8],
        ivs: &[Block],
        keys: &OpenCLKeys,
        aes_iterations: u32,
        breadth_iterations: u32,
    ) -> Result<Vec<u8>> {
        assert!(input.len() % PIECE_SIZE == 0);

        let blocks_count = input.len() / PIECE_SIZE;
        assert!(blocks_count == ivs.len());

        let buffer_state = Self::validate_or_allocate_buffer::<Uchar16>(
            &self.context,
            &mut self.buffer_state,
            input.len(),
            flags::MEM_READ_WRITE | flags::MEM_ALLOC_HOST_PTR,
        )?;

        let buffer_ivs = Self::validate_or_allocate_buffer::<Uchar16>(
            &self.context,
            &mut self.buffer_iv,
            ivs.len(),
            flags::MEM_READ_WRITE | flags::MEM_ALLOC_HOST_PTR,
        )?;

        set_kernel_arg(&self.por_128_dec_kernel, 0, ArgVal::mem(&buffer_state))?;
        set_kernel_arg(&self.por_128_dec_kernel, 1, ArgVal::mem(&buffer_ivs))?;
        set_kernel_arg(&self.por_128_dec_kernel, 3, ArgVal::scalar(&aes_iterations))?;
        set_kernel_arg(
            &self.por_128_dec_kernel,
            4,
            ArgVal::scalar(&breadth_iterations),
        )?;

        unsafe {
            enqueue_write_buffer(
                &self.queue,
                &buffer_state,
                true,
                0,
                &utils::inputs_to_uchar16_vec(input),
                None::<Event>,
                None::<&mut Event>,
            )?;
        }

        unsafe {
            enqueue_write_buffer(
                &self.queue,
                &buffer_ivs,
                true,
                0,
                &utils::ivs_to_uchar16_vec(&ivs),
                None::<Event>,
                None::<&mut Event>,
            )?;
        }

        unsafe {
            enqueue_write_buffer(
                &self.queue,
                &self.buffer_round_keys,
                true,
                0,
                &utils::keys_to_uint_vec(&keys.keys_dec),
                None::<Event>,
                None::<&mut Event>,
            )?;
        }

        unsafe {
            enqueue_kernel(
                &self.queue,
                &self.por_128_dec_kernel,
                1,
                None,
                // TODO: This will not handle too big inputs that exceed VRAM
                &[blocks_count, 0, 0],
                None,
                None::<Event>,
                None::<&mut Event>,
            )
        }?;

        let mut output = Vec::<u8>::with_capacity(input.len());
        {
            let mut result = Uchar16::from([0u8; BLOCK_SIZE]);
            for offset in (0..input.len()).step_by(BLOCK_SIZE) {
                unsafe {
                    enqueue_read_buffer(
                        &self.queue,
                        &buffer_state,
                        true,
                        offset,
                        &mut result,
                        None::<Event>,
                        None::<&mut Event>,
                    )?;
                }
                output.extend_from_slice(&result);
            }
        }

        finish(&self.queue)?;

        Ok(output)
    }

    fn validate_or_allocate_buffer<T: OclPrm>(
        context: &Context,
        buffer: &mut Option<CachedBuffer>,
        buffer_size: usize,
        flags: MemFlags,
    ) -> Result<Mem> {
        if let Some(cached_buffer) = buffer {
            if cached_buffer.buffer_size == buffer_size {
                return Ok(cached_buffer.mem.clone());
            }
        }

        let mem = unsafe { create_buffer(context, flags, buffer_size, None::<&[T]>)? };
        buffer.replace({
            let mem = mem.clone();
            CachedBuffer { mem, buffer_size }
        });

        Ok(mem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::por::test_data::CORRECT_ENCODING;
    use crate::por::test_data::CORRECT_ENCODING_BREADTH_10;
    use crate::por::test_data::ID;
    use crate::por::test_data::INPUT;
    use crate::por::test_data::IV;
    use rand::Rng;

    #[test]
    fn test_simple() {
        let mut codec = OpenCL::new().unwrap();

        let keys = OpenCLKeys::new(&ID);

        let encryption = codec.encode(&INPUT, &[IV], &keys, 256, 1).unwrap();
        assert_eq!(encryption, CORRECT_ENCODING.to_vec());

        let ivs = vec![IV, IV];
        let encryptions = codec
            .encode(
                &(0..2)
                    .flat_map(|_| INPUT.as_ref().to_vec())
                    .collect::<Vec<u8>>()
                    .as_ref(),
                &ivs,
                &keys,
                256,
                1,
            )
            .unwrap();
        assert_eq!(
            encryptions[PIECE_SIZE..].to_vec(),
            encryptions[..PIECE_SIZE].to_vec(),
        );
        assert_eq!(
            encryptions[PIECE_SIZE..].to_vec(),
            CORRECT_ENCODING.to_vec(),
        );

        let decryption = codec.decode(&encryption, &[IV], &keys, 256, 1).unwrap();
        assert_eq!(decryption, INPUT.to_vec());

        let decryptions = codec.decode(&encryptions, &ivs, &keys, 256, 1).unwrap();
        assert_eq!(
            decryptions[PIECE_SIZE..].to_vec(),
            decryptions[..PIECE_SIZE].to_vec(),
        );
        assert_eq!(INPUT.to_vec(), decryptions[PIECE_SIZE..].to_vec());
    }

    #[test]
    fn test_breadth_10() {
        let mut codec = OpenCL::new().unwrap();

        let keys = OpenCLKeys::new(&ID);

        let encryption = codec.encode(&INPUT, &[IV], &keys, 256, 10).unwrap();
        assert_eq!(encryption, CORRECT_ENCODING_BREADTH_10.to_vec());

        let ivs = vec![IV, IV];
        let encryptions = codec
            .encode(
                &(0..2)
                    .flat_map(|_| INPUT.as_ref().to_vec())
                    .collect::<Vec<u8>>()
                    .as_ref(),
                &ivs,
                &keys,
                256,
                10,
            )
            .unwrap();
        assert_eq!(
            encryptions[PIECE_SIZE..].to_vec(),
            encryptions[..PIECE_SIZE].to_vec(),
        );
        assert_eq!(
            encryptions[PIECE_SIZE..].to_vec(),
            CORRECT_ENCODING_BREADTH_10.to_vec(),
        );

        let decryption = codec.decode(&encryption, &[IV], &keys, 256, 10).unwrap();
        assert_eq!(decryption, INPUT.to_vec());

        let decryptions = codec.decode(&encryptions, &ivs, &keys, 256, 10).unwrap();
        assert_eq!(
            decryptions[PIECE_SIZE..].to_vec(),
            decryptions[..PIECE_SIZE].to_vec(),
        );
        assert_eq!(INPUT.to_vec(), decryptions[PIECE_SIZE..].to_vec());
    }

    #[test]
    fn test_random_simple() {
        let mut codec = OpenCL::new().unwrap();

        let mut id = [0u8; 16];
        rand::thread_rng().fill(&mut id[..]);

        let mut input = [0u8; PIECE_SIZE];
        rand::thread_rng().fill(&mut input[..]);

        let mut iv = [0u8; 16];
        rand::thread_rng().fill(&mut iv[..]);

        let keys = OpenCLKeys::new(&id);

        let encryption = codec.encode(&input, &[iv], &keys, 256, 1).unwrap();

        let ivs = vec![iv, iv];
        let encryptions = codec
            .encode(
                &(0..2)
                    .flat_map(|_| input.as_ref().to_vec())
                    .collect::<Vec<u8>>()
                    .as_ref(),
                &ivs,
                &keys,
                256,
                1,
            )
            .unwrap();

        for single_encryption in encryptions.chunks_exact(PIECE_SIZE) {
            assert_eq!(single_encryption.to_vec(), encryption.to_vec(),);
        }

        let decryption = codec.decode(&encryption, &[iv], &keys, 256, 1).unwrap();
        assert_eq!(decryption, input.to_vec());

        let decryptions = codec.decode(&encryptions, &ivs, &keys, 256, 1).unwrap();

        for decryption in decryptions.chunks_exact(PIECE_SIZE) {
            assert_eq!(decryption.to_vec(), input.to_vec(),);
        }
    }

    #[test]
    fn test_random_breadth_10() {
        let mut codec = OpenCL::new().unwrap();

        let mut id = [0u8; 16];
        rand::thread_rng().fill(&mut id[..]);

        let mut input = [0u8; PIECE_SIZE];
        rand::thread_rng().fill(&mut input[..]);

        let mut iv = [0u8; 16];
        rand::thread_rng().fill(&mut iv[..]);

        let keys = OpenCLKeys::new(&id);

        let encryption = codec.encode(&input, &[iv], &keys, 256, 10).unwrap();

        let ivs = vec![iv, iv];
        let encryptions = codec
            .encode(
                &(0..2)
                    .flat_map(|_| input.as_ref().to_vec())
                    .collect::<Vec<u8>>()
                    .as_ref(),
                &ivs,
                &keys,
                256,
                10,
            )
            .unwrap();

        for single_encryption in encryptions.chunks_exact(PIECE_SIZE) {
            assert_eq!(single_encryption.to_vec(), encryption.to_vec(),);
        }

        let decryption = codec.decode(&encryption, &[iv], &keys, 256, 10).unwrap();
        assert_eq!(decryption, input.to_vec());

        let decryptions = codec.decode(&encryptions, &ivs, &keys, 256, 10).unwrap();

        for decryption in decryptions.chunks_exact(PIECE_SIZE) {
            assert_eq!(decryption.to_vec(), input.to_vec(),);
        }
    }
}
