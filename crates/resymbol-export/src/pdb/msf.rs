//! Deterministic, bounded writer for the MSF 7.00 container used by PDB files.
//!
//! This is deliberately a from-scratch writer, not a transactional MSF editor.
//! It implements the 4 KiB "Big MSF" layout documented by LLVM and caps output
//! at one complete free-page-map bitmap (32,768 blocks / 128 MiB). Keeping that
//! bound makes the layout small enough to audit while still covering practical
//! synthetic public-symbol PDBs.
//!
//! Format references:
//! - <https://llvm.org/docs/PDB/MsfFile.html>
//! - `llvm/lib/DebugInfo/MSF/MSFBuilder.cpp`
//! - `microsoft/microsoft-pdb`, `PDB/msf/msf.cpp`

use std::error::Error;
use std::fmt;

const BLOCK_SIZE: u32 = 4_096;
const BLOCK_SIZE_USIZE: usize = BLOCK_SIZE as usize;
const MAX_BLOCKS: u32 = BLOCK_SIZE * 8;
const MAX_STREAMS: usize = u16::MAX as usize;
const MAX_DIRECTORY_BLOCKS: u32 = BLOCK_SIZE / 4;
const NIL_STREAM_SIZE: u32 = u32::MAX;

const SUPER_BLOCK: u32 = 0;
const ALTERNATE_FPM_BLOCK: u32 = 1;
const ACTIVE_FPM_BLOCK: u32 = 2;
const DIRECTORY_BLOCK_MAP: u32 = 3;
const FIRST_ALLOCATABLE_BLOCK: u32 = 4;

const MSF_700_MAGIC: [u8; 32] = *b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";

/// A checked failure to represent streams in the bounded MSF 7.00 layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum MsfError {
    TooManyStreams {
        actual: usize,
        maximum: usize,
    },
    InvalidStreamZero,
    StreamTooLarge {
        stream: usize,
        bytes: u64,
        maximum: u64,
    },
    StreamUsesNilSize {
        stream: usize,
    },
    DirectoryTooLarge {
        blocks: u64,
        maximum: u32,
    },
    FileTooLarge {
        required_blocks: u64,
        maximum_blocks: u32,
    },
    IntegerOverflow {
        context: &'static str,
    },
    AllocationFailed {
        context: &'static str,
    },
    InvalidLayout {
        context: &'static str,
    },
}

impl fmt::Display for MsfError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyStreams { actual, maximum } => write!(
                formatter,
                "MSF stream count {actual} exceeds the supported maximum {maximum}"
            ),
            Self::InvalidStreamZero => {
                write!(formatter, "MSF fixed stream 0 must be present and empty")
            }
            Self::StreamTooLarge {
                stream,
                bytes,
                maximum,
            } => write!(
                formatter,
                "MSF stream {stream} has {bytes} bytes, exceeding the maximum {maximum}"
            ),
            Self::StreamUsesNilSize { stream } => write!(
                formatter,
                "MSF stream {stream} has size 0xffffffff, which is reserved for nil streams"
            ),
            Self::DirectoryTooLarge { blocks, maximum } => write!(
                formatter,
                "MSF stream directory needs {blocks} blocks, exceeding the one-block map capacity {maximum}"
            ),
            Self::FileTooLarge {
                required_blocks,
                maximum_blocks,
            } => write!(
                formatter,
                "MSF output needs at least {required_blocks} blocks, exceeding the supported maximum {maximum_blocks}"
            ),
            Self::IntegerOverflow { context } => {
                write!(formatter, "integer overflow while computing {context}")
            }
            Self::AllocationFailed { context } => {
                write!(
                    formatter,
                    "memory allocation failed while building {context}"
                )
            }
            Self::InvalidLayout { context } => {
                write!(formatter, "internal MSF layout is invalid: {context}")
            }
        }
    }
}

impl Error for MsfError {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlannedStream {
    size: u32,
    blocks: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MsfLayout {
    streams: Vec<PlannedStream>,
    directory_size: u32,
    directory_blocks: Vec<u32>,
    num_blocks: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlockAllocator {
    next: u32,
}

impl BlockAllocator {
    const fn new() -> Self {
        Self {
            next: FIRST_ALLOCATABLE_BLOCK,
        }
    }

    fn allocate(&mut self, count: u32) -> Result<Vec<u32>, MsfError> {
        let capacity = usize::try_from(count).map_err(|_| MsfError::IntegerOverflow {
            context: "MSF block-list capacity",
        })?;
        let mut blocks = Vec::new();
        blocks
            .try_reserve_exact(capacity)
            .map_err(|_| MsfError::AllocationFailed {
                context: "MSF block list",
            })?;

        for _ in 0..count {
            while is_fpm_block(self.next) {
                self.next = self.next.checked_add(1).ok_or(MsfError::IntegerOverflow {
                    context: "MSF reserved FPM block",
                })?;
            }

            if self.next >= MAX_BLOCKS {
                return Err(MsfError::FileTooLarge {
                    required_blocks: u64::from(self.next) + 1,
                    maximum_blocks: MAX_BLOCKS,
                });
            }

            blocks.push(self.next);
            self.next = self.next.checked_add(1).ok_or(MsfError::IntegerOverflow {
                context: "MSF block allocation",
            })?;
        }

        Ok(blocks)
    }
}

/// Write a complete, zero-padded MSF 7.00 container in memory.
///
/// `None` represents a nil stream (`0xffffffff` in the stream directory),
/// while `Some(Vec::new())` represents a present stream with length zero.
/// Fixed stream 0 must be present and empty. Readers treat it as the obsolete
/// stream-directory slot and do not account for any blocks listed there.
pub(super) fn write_msf(streams: &[Option<Vec<u8>>]) -> Result<Vec<u8>, MsfError> {
    if streams.len() > MAX_STREAMS {
        return Err(MsfError::TooManyStreams {
            actual: streams.len(),
            maximum: MAX_STREAMS,
        });
    }
    if !matches!(streams.first(), Some(Some(bytes)) if bytes.is_empty()) {
        return Err(MsfError::InvalidStreamZero);
    }

    let mut stream_sizes = Vec::new();
    stream_sizes
        .try_reserve_exact(streams.len())
        .map_err(|_| MsfError::AllocationFailed {
            context: "MSF stream-size plan",
        })?;
    for stream in streams {
        stream_sizes.push(
            stream
                .as_ref()
                .map(|bytes| u64::try_from(bytes.len()))
                .transpose()
                .map_err(|_| MsfError::IntegerOverflow {
                    context: "MSF input stream length",
                })?,
        );
    }

    let layout = plan_layout(&stream_sizes)?;
    let file_size = usize::try_from(layout.num_blocks)
        .ok()
        .and_then(|blocks| blocks.checked_mul(BLOCK_SIZE_USIZE))
        .ok_or(MsfError::IntegerOverflow {
            context: "MSF output byte size",
        })?;

    let mut output = Vec::new();
    output
        .try_reserve_exact(file_size)
        .map_err(|_| MsfError::AllocationFailed {
            context: "MSF output",
        })?;
    output.resize(file_size, 0);

    write_superblock(&mut output, &layout)?;
    write_free_page_maps(&mut output, layout.num_blocks)?;

    for (input, planned) in streams.iter().zip(&layout.streams) {
        match (input.as_deref(), planned.size) {
            (None, NIL_STREAM_SIZE) => {}
            (Some(bytes), size) if bytes.len() == size as usize => {
                write_scattered(&mut output, &planned.blocks, bytes)?;
            }
            _ => {
                return Err(MsfError::InvalidLayout {
                    context: "planned stream no longer matches its input",
                });
            }
        }
    }

    let directory = serialize_directory(&layout)?;
    write_scattered(&mut output, &layout.directory_blocks, &directory)?;
    write_directory_block_map(&mut output, &layout.directory_blocks)?;

    Ok(output)
}

fn plan_layout(sizes: &[Option<u64>]) -> Result<MsfLayout, MsfError> {
    if sizes.len() > MAX_STREAMS {
        return Err(MsfError::TooManyStreams {
            actual: sizes.len(),
            maximum: MAX_STREAMS,
        });
    }

    let mut shapes = Vec::new();
    shapes
        .try_reserve_exact(sizes.len())
        .map_err(|_| MsfError::AllocationFailed {
            context: "MSF stream layout",
        })?;
    let mut total_stream_blocks = 0_u64;

    for (stream, size) in sizes.iter().copied().enumerate() {
        let (encoded_size, block_count) = match size {
            None => (NIL_STREAM_SIZE, 0_u32),
            Some(bytes) => {
                if bytes > u64::from(u32::MAX) {
                    return Err(MsfError::StreamTooLarge {
                        stream,
                        bytes,
                        maximum: u64::from(u32::MAX) - 1,
                    });
                }
                if bytes == u64::from(NIL_STREAM_SIZE) {
                    return Err(MsfError::StreamUsesNilSize { stream });
                }
                let blocks = bytes.div_ceil(u64::from(BLOCK_SIZE));
                let blocks = u32::try_from(blocks).map_err(|_| MsfError::IntegerOverflow {
                    context: "MSF stream block count",
                })?;
                (bytes as u32, blocks)
            }
        };

        total_stream_blocks = total_stream_blocks
            .checked_add(u64::from(block_count))
            .ok_or(MsfError::IntegerOverflow {
                context: "MSF aggregate stream blocks",
            })?;
        shapes.push((encoded_size, block_count));
    }

    let directory_size = 4_u64
        .checked_add(
            u64::try_from(sizes.len())
                .map_err(|_| MsfError::IntegerOverflow {
                    context: "MSF stream count",
                })?
                .checked_mul(4)
                .ok_or(MsfError::IntegerOverflow {
                    context: "MSF stream-size table",
                })?,
        )
        .and_then(|size| size.checked_add(total_stream_blocks.checked_mul(4)?))
        .ok_or(MsfError::IntegerOverflow {
            context: "MSF stream directory size",
        })?;
    let directory_size = u32::try_from(directory_size).map_err(|_| MsfError::IntegerOverflow {
        context: "MSF stream directory u32 size",
    })?;
    let directory_block_count = u64::from(directory_size).div_ceil(u64::from(BLOCK_SIZE));
    if directory_block_count > u64::from(MAX_DIRECTORY_BLOCKS) {
        return Err(MsfError::DirectoryTooLarge {
            blocks: directory_block_count,
            maximum: MAX_DIRECTORY_BLOCKS,
        });
    }
    let directory_block_count =
        u32::try_from(directory_block_count).map_err(|_| MsfError::IntegerOverflow {
            context: "MSF directory block count",
        })?;

    let minimum_blocks = u64::from(FIRST_ALLOCATABLE_BLOCK)
        .checked_add(total_stream_blocks)
        .and_then(|blocks| blocks.checked_add(u64::from(directory_block_count)))
        .ok_or(MsfError::IntegerOverflow {
            context: "MSF minimum file block count",
        })?;
    if minimum_blocks > u64::from(MAX_BLOCKS) {
        return Err(MsfError::FileTooLarge {
            required_blocks: minimum_blocks,
            maximum_blocks: MAX_BLOCKS,
        });
    }

    let mut allocator = BlockAllocator::new();
    let mut planned_streams = Vec::new();
    planned_streams
        .try_reserve_exact(shapes.len())
        .map_err(|_| MsfError::AllocationFailed {
            context: "MSF planned streams",
        })?;
    for (size, block_count) in shapes {
        planned_streams.push(PlannedStream {
            size,
            blocks: allocator.allocate(block_count)?,
        });
    }
    let directory_blocks = allocator.allocate(directory_block_count)?;

    if allocator.next == 0 || allocator.next > MAX_BLOCKS {
        return Err(MsfError::FileTooLarge {
            required_blocks: u64::from(allocator.next),
            maximum_blocks: MAX_BLOCKS,
        });
    }

    Ok(MsfLayout {
        streams: planned_streams,
        directory_size,
        directory_blocks,
        num_blocks: allocator.next,
    })
}

const fn is_fpm_block(block: u32) -> bool {
    let phase = block % BLOCK_SIZE;
    phase == ALTERNATE_FPM_BLOCK || phase == ACTIVE_FPM_BLOCK
}

fn write_superblock(output: &mut [u8], layout: &MsfLayout) -> Result<(), MsfError> {
    let superblock = block_mut(output, SUPER_BLOCK)?;
    superblock[..MSF_700_MAGIC.len()].copy_from_slice(&MSF_700_MAGIC);
    put_u32(superblock, 32, BLOCK_SIZE)?;
    put_u32(superblock, 36, ACTIVE_FPM_BLOCK)?;
    put_u32(superblock, 40, layout.num_blocks)?;
    put_u32(superblock, 44, layout.directory_size)?;
    put_u32(superblock, 48, 0)?;
    put_u32(superblock, 52, DIRECTORY_BLOCK_MAP)?;
    Ok(())
}

fn write_free_page_maps(output: &mut [u8], num_blocks: u32) -> Result<(), MsfError> {
    if num_blocks == 0 || num_blocks > MAX_BLOCKS {
        return Err(MsfError::InvalidLayout {
            context: "FPM block count is outside the supported range",
        });
    }

    let mut bitmap = [0xff_u8; BLOCK_SIZE_USIZE];
    for block in 0..num_blocks {
        let byte = usize::try_from(block / 8).map_err(|_| MsfError::IntegerOverflow {
            context: "MSF FPM byte offset",
        })?;
        bitmap[byte] &= !(1_u8 << (block % 8));
    }
    block_mut(output, ALTERNATE_FPM_BLOCK)?.copy_from_slice(&bitmap);
    block_mut(output, ACTIVE_FPM_BLOCK)?.copy_from_slice(&bitmap);

    // MSF reserves an FPM pair in every 4,096-block interval even though
    // this bounded file needs only the first bitmap page. Make unused FPM
    // fragments canonically describe blocks beyond EOF as free.
    let mut interval_start = BLOCK_SIZE;
    while interval_start < num_blocks {
        for phase in [ALTERNATE_FPM_BLOCK, ACTIVE_FPM_BLOCK] {
            let block = interval_start
                .checked_add(phase)
                .ok_or(MsfError::IntegerOverflow {
                    context: "MSF trailing FPM block",
                })?;
            if block < num_blocks {
                block_mut(output, block)?.fill(0xff);
            }
        }
        interval_start =
            interval_start
                .checked_add(BLOCK_SIZE)
                .ok_or(MsfError::IntegerOverflow {
                    context: "MSF FPM interval",
                })?;
    }

    Ok(())
}

fn serialize_directory(layout: &MsfLayout) -> Result<Vec<u8>, MsfError> {
    let capacity =
        usize::try_from(layout.directory_size).map_err(|_| MsfError::IntegerOverflow {
            context: "MSF directory allocation size",
        })?;
    let mut directory = Vec::new();
    directory
        .try_reserve_exact(capacity)
        .map_err(|_| MsfError::AllocationFailed {
            context: "MSF stream directory",
        })?;

    push_u32(
        &mut directory,
        u32::try_from(layout.streams.len()).map_err(|_| MsfError::IntegerOverflow {
            context: "MSF encoded stream count",
        })?,
    );
    for stream in &layout.streams {
        push_u32(&mut directory, stream.size);
    }
    for stream in &layout.streams {
        for block in &stream.blocks {
            push_u32(&mut directory, *block);
        }
    }

    if directory.len() != capacity {
        return Err(MsfError::InvalidLayout {
            context: "serialized directory length disagrees with its plan",
        });
    }
    Ok(directory)
}

fn write_directory_block_map(output: &mut [u8], blocks: &[u32]) -> Result<(), MsfError> {
    if blocks.len() > MAX_DIRECTORY_BLOCKS as usize {
        return Err(MsfError::InvalidLayout {
            context: "directory block map exceeds one block",
        });
    }
    let block_map = block_mut(output, DIRECTORY_BLOCK_MAP)?;
    for (index, block) in blocks.iter().copied().enumerate() {
        let offset = index.checked_mul(4).ok_or(MsfError::IntegerOverflow {
            context: "MSF directory block-map offset",
        })?;
        put_u32(block_map, offset, block)?;
    }
    Ok(())
}

fn write_scattered(output: &mut [u8], blocks: &[u32], data: &[u8]) -> Result<(), MsfError> {
    let required_blocks = data.len().div_ceil(BLOCK_SIZE_USIZE);
    if required_blocks != blocks.len() {
        return Err(MsfError::InvalidLayout {
            context: "scatter block count does not match data length",
        });
    }

    for (block, chunk) in blocks.iter().copied().zip(data.chunks(BLOCK_SIZE_USIZE)) {
        let destination = block_mut(output, block)?;
        destination[..chunk.len()].copy_from_slice(chunk);
    }
    Ok(())
}

fn block_mut(output: &mut [u8], block: u32) -> Result<&mut [u8], MsfError> {
    let start = usize::try_from(block)
        .ok()
        .and_then(|block| block.checked_mul(BLOCK_SIZE_USIZE))
        .ok_or(MsfError::IntegerOverflow {
            context: "MSF block byte offset",
        })?;
    let end = start
        .checked_add(BLOCK_SIZE_USIZE)
        .ok_or(MsfError::IntegerOverflow {
            context: "MSF block byte range",
        })?;
    output.get_mut(start..end).ok_or(MsfError::InvalidLayout {
        context: "block falls outside the output buffer",
    })
}

fn put_u32(output: &mut [u8], offset: usize, value: u32) -> Result<(), MsfError> {
    let end = offset.checked_add(4).ok_or(MsfError::IntegerOverflow {
        context: "MSF u32 byte range",
    })?;
    let destination = output.get_mut(offset..end).ok_or(MsfError::InvalidLayout {
        context: "u32 field falls outside its destination",
    })?;
    destination.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    const TEST_BLOCK_SIZE: usize = 4_096;
    const TEST_NIL_SIZE: u32 = 0xffff_ffff;

    #[derive(Debug)]
    struct DecodedMsf {
        stream_sizes: Vec<u32>,
        stream_blocks: Vec<Vec<u32>>,
        directory_blocks: Vec<u32>,
        num_blocks: u32,
        directory_size: u32,
    }

    impl DecodedMsf {
        fn streams(&self, file: &[u8]) -> Vec<Option<Vec<u8>>> {
            self.stream_sizes
                .iter()
                .copied()
                .zip(&self.stream_blocks)
                .map(|(size, blocks)| {
                    if size == TEST_NIL_SIZE {
                        return None;
                    }
                    let mut data = Vec::with_capacity(size as usize);
                    for block in blocks {
                        let start = *block as usize * TEST_BLOCK_SIZE;
                        let remaining = size as usize - data.len();
                        let take = remaining.min(TEST_BLOCK_SIZE);
                        data.extend_from_slice(&file[start..start + take]);
                    }
                    Some(data)
                })
                .collect()
        }
    }

    fn decode_independently(file: &[u8]) -> DecodedMsf {
        assert!(file.len() >= TEST_BLOCK_SIZE);
        assert_eq!(&file[..32], b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0");
        assert_eq!(read_u32(file, 32), 4_096);
        assert!(matches!(read_u32(file, 36), 1 | 2));
        let num_blocks = read_u32(file, 40);
        assert_eq!(file.len(), num_blocks as usize * TEST_BLOCK_SIZE);
        let directory_size = read_u32(file, 44);
        assert_eq!(directory_size % 4, 0);
        assert_eq!(read_u32(file, 48), 0);
        let block_map = read_u32(file, 52);
        assert!(block_map < num_blocks);
        assert_ne!(block_map, 0);
        assert!(!is_reserved_fpm_independent(block_map));

        let directory_block_count = (directory_size as usize).div_ceil(TEST_BLOCK_SIZE);
        assert!(directory_block_count <= TEST_BLOCK_SIZE / 4);
        let mut directory_blocks = Vec::with_capacity(directory_block_count);
        let map_start = block_map as usize * TEST_BLOCK_SIZE;
        for index in 0..directory_block_count {
            let block = read_u32(file, map_start + index * 4);
            assert!(block < num_blocks);
            assert!(!is_reserved_fpm_independent(block));
            directory_blocks.push(block);
        }

        let mut directory = Vec::with_capacity(directory_size as usize);
        for block in &directory_blocks {
            let start = *block as usize * TEST_BLOCK_SIZE;
            let remaining = directory_size as usize - directory.len();
            let take = remaining.min(TEST_BLOCK_SIZE);
            directory.extend_from_slice(&file[start..start + take]);
        }
        assert_eq!(directory.len(), directory_size as usize);

        let stream_count = read_u32(&directory, 0) as usize;
        let sizes_end = 4 + stream_count * 4;
        assert!(sizes_end <= directory.len());
        let mut stream_sizes = Vec::with_capacity(stream_count);
        for index in 0..stream_count {
            stream_sizes.push(read_u32(&directory, 4 + index * 4));
        }

        let mut cursor = sizes_end;
        let mut stream_blocks = Vec::with_capacity(stream_count);
        let mut occupied = BTreeSet::from([0_u32, 1, 2, block_map]);
        for block in &directory_blocks {
            assert!(occupied.insert(*block), "directory block is reused");
        }
        for size in &stream_sizes {
            let count = if *size == TEST_NIL_SIZE {
                0
            } else {
                (*size as usize).div_ceil(TEST_BLOCK_SIZE)
            };
            let mut blocks = Vec::with_capacity(count);
            for _ in 0..count {
                assert!(cursor + 4 <= directory.len());
                let block = read_u32(&directory, cursor);
                cursor += 4;
                assert!(block < num_blocks);
                assert!(!is_reserved_fpm_independent(block));
                assert!(occupied.insert(block), "stream block is reused");
                blocks.push(block);
            }
            stream_blocks.push(blocks);
        }
        assert_eq!(cursor, directory.len());

        DecodedMsf {
            stream_sizes,
            stream_blocks,
            directory_blocks,
            num_blocks,
            directory_size,
        }
    }

    fn read_u32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("u32 bytes"))
    }

    fn is_reserved_fpm_independent(block: u32) -> bool {
        matches!(block % 4_096, 1 | 2)
    }

    #[test]
    fn distinguishes_nil_empty_and_present_streams() {
        let streams = vec![Some(Vec::new()), None, Some(b"abc".to_vec())];
        let file = write_msf(&streams).expect("write MSF");
        let decoded = decode_independently(&file);

        assert_eq!(decoded.stream_sizes, [0, TEST_NIL_SIZE, 3]);
        assert!(decoded.stream_blocks[0].is_empty());
        assert!(decoded.stream_blocks[1].is_empty());
        assert_eq!(decoded.stream_blocks[2], [4]);
        assert_eq!(decoded.directory_blocks, [5]);
        assert_eq!(decoded.directory_size, 20);
        assert_eq!(decoded.num_blocks, 6);
        assert_eq!(decoded.streams(&file), streams);
    }

    #[test]
    fn writes_exact_superblock_and_file_length() {
        let file = write_msf(&[Some(Vec::new()), Some(b"hello".to_vec())]).expect("write MSF");
        let decoded = decode_independently(&file);

        assert_eq!(read_u32(&file, 36), 2);
        assert_eq!(read_u32(&file, 40), decoded.num_blocks);
        assert_eq!(read_u32(&file, 44), decoded.directory_size);
        assert_eq!(read_u32(&file, 48), 0);
        assert_eq!(read_u32(&file, 52), 3);
        assert!(file[56..TEST_BLOCK_SIZE].iter().all(|byte| *byte == 0));
        assert_eq!(file.len(), decoded.num_blocks as usize * TEST_BLOCK_SIZE);
    }

    #[test]
    fn round_trips_streams_at_block_boundaries() {
        let make = |size: usize, seed: u8| {
            (0..size)
                .map(|index| seed.wrapping_add(index as u8))
                .collect::<Vec<_>>()
        };
        let streams = vec![
            Some(Vec::new()),
            Some(make(4_095, 3)),
            Some(make(4_096, 7)),
            Some(make(4_097, 11)),
        ];
        let file = write_msf(&streams).expect("write MSF");
        let decoded = decode_independently(&file);

        assert_eq!(decoded.stream_blocks[0].len(), 0);
        assert_eq!(decoded.stream_blocks[1].len(), 1);
        assert_eq!(decoded.stream_blocks[2].len(), 1);
        assert_eq!(decoded.stream_blocks[3].len(), 2);
        assert_eq!(decoded.streams(&file), streams);
    }

    #[test]
    fn writes_a_directory_that_spans_blocks() {
        let streams = vec![Some(Vec::new()); 1_100];
        let file = write_msf(&streams).expect("write MSF");
        let decoded = decode_independently(&file);

        assert_eq!(decoded.directory_size, 4 + 1_100 * 4);
        assert_eq!(decoded.directory_blocks, [4, 5]);
        assert_eq!(decoded.streams(&file), streams);
    }

    #[test]
    fn allocator_skips_every_later_fpm_pair() {
        let mut allocator = BlockAllocator { next: 4_095 };
        let blocks = allocator.allocate(4).expect("allocate across interval");

        assert_eq!(blocks, [4_095, 4_096, 4_099, 4_100]);
        assert_eq!(allocator.next, 4_101);
    }

    #[test]
    fn fpm_is_lsb_first_duplicated_and_marks_beyond_eof_free() {
        let file = write_msf(&[Some(Vec::new()), Some(b"x".to_vec())]).expect("write MSF");
        let num_blocks = read_u32(&file, 40);
        let first = &file[TEST_BLOCK_SIZE..2 * TEST_BLOCK_SIZE];
        let second = &file[2 * TEST_BLOCK_SIZE..3 * TEST_BLOCK_SIZE];

        assert_eq!(first, second);
        for block in 0..num_blocks {
            assert_eq!(first[(block / 8) as usize] & (1 << (block % 8)), 0);
        }
        for block in num_blocks..num_blocks + 32 {
            assert_ne!(first[(block / 8) as usize] & (1 << (block % 8)), 0);
        }
    }

    #[test]
    fn unused_later_fpm_fragments_are_canonical_free_pages() {
        let num_blocks = 4_100_u32;
        let mut file = vec![0_u8; num_blocks as usize * TEST_BLOCK_SIZE];
        write_free_page_maps(&mut file, num_blocks).expect("write FPMs");

        for block in [4_097_u32, 4_098] {
            let start = block as usize * TEST_BLOCK_SIZE;
            assert!(
                file[start..start + TEST_BLOCK_SIZE]
                    .iter()
                    .all(|byte| *byte == 0xff)
            );
        }
        let primary = &file[TEST_BLOCK_SIZE..2 * TEST_BLOCK_SIZE];
        for block in [4_097_u32, 4_098] {
            assert_eq!(
                primary[(block / 8) as usize] & (1 << (block % 8)),
                0,
                "in-file reserved FPM block remains busy"
            );
        }
    }

    #[test]
    fn output_is_deterministic_and_zero_padded() {
        let streams = vec![Some(Vec::new()), Some(b"deterministic".to_vec()), None];
        let first = write_msf(&streams).expect("first MSF");
        let second = write_msf(&streams).expect("second MSF");
        assert_eq!(first, second);

        let decoded = decode_independently(&first);
        let data_block = decoded.stream_blocks[1][0] as usize * TEST_BLOCK_SIZE;
        assert!(
            first[data_block + b"deterministic".len()..data_block + TEST_BLOCK_SIZE]
                .iter()
                .all(|byte| *byte == 0)
        );
        let map_start = 3 * TEST_BLOCK_SIZE;
        assert!(
            first[map_start + decoded.directory_blocks.len() * 4..map_start + TEST_BLOCK_SIZE]
                .iter()
                .all(|byte| *byte == 0)
        );
    }

    #[test]
    fn rejects_unrepresentable_layouts_without_large_allocations() {
        let too_many = vec![None; MAX_STREAMS + 1];
        assert!(matches!(
            plan_layout(&too_many),
            Err(MsfError::TooManyStreams { .. })
        ));

        assert!(matches!(
            plan_layout(&[Some(u64::from(u32::MAX))]),
            Err(MsfError::StreamUsesNilSize { stream: 0 })
        ));

        assert!(matches!(
            plan_layout(&[Some(u64::from(MAX_BLOCKS) * u64::from(BLOCK_SIZE))]),
            Err(MsfError::FileTooLarge { .. })
        ));

        assert!(matches!(
            plan_layout(&[Some(u64::from(u32::MAX) + 1)]),
            Err(MsfError::StreamTooLarge { stream: 0, .. })
        ));
    }

    #[test]
    fn rejects_missing_nil_or_nonempty_stream_zero() {
        assert!(matches!(write_msf(&[]), Err(MsfError::InvalidStreamZero)));
        assert!(matches!(
            write_msf(&[None]),
            Err(MsfError::InvalidStreamZero)
        ));
        assert!(matches!(
            write_msf(&[Some(b"old directory".to_vec())]),
            Err(MsfError::InvalidStreamZero)
        ));
    }
}
