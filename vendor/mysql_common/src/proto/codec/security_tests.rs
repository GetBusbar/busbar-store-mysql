//! Regression tests retain the official codec API so the same tests run on its preimage.
use super::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct ObservedAllocator;
static WATCHED: AtomicUsize = AtomicUsize::new(0);
static WATCHED_LEN: AtomicUsize = AtomicUsize::new(0);
static SAW_FREE: AtomicBool = AtomicBool::new(false);
static NONZERO: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if WATCHED
            .compare_exchange(ptr as usize, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            let len = WATCHED_LEN.load(Ordering::SeqCst).min(layout.size());
            // The test only watches initialized bytes in a live allocation, immediately
            // BEFORE System frees it. No freed or uninitialized memory is inspected.
            let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
            NONZERO.store(bytes.iter().filter(|&&b| b != 0).count(), Ordering::SeqCst);
            SAW_FREE.store(true, Ordering::SeqCst);
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

fn watch(buf: &BytesMut) {
    assert_eq!(WATCHED.load(Ordering::SeqCst), 0);
    SAW_FREE.store(false, Ordering::SeqCst);
    NONZERO.store(usize::MAX, Ordering::SeqCst);
    WATCHED_LEN.store(buf.len(), Ordering::SeqCst);
    WATCHED.store(buf.as_ptr() as usize, Ordering::SeqCst);
}

fn assert_wiped_before_free() {
    assert!(
        SAW_FREE.load(Ordering::SeqCst),
        "the observed allocation must actually be released"
    );
    assert_eq!(WATCHED.load(Ordering::SeqCst), 0);
    assert_eq!(
        NONZERO.load(Ordering::SeqCst),
        0,
        "plaintext remained at deallocation"
    );
}

#[test]
fn security_plain_consumed_prefix_wiped() {
    let secret = b"credential-plaintext";
    let mut src = BytesMut::new();
    src.put_u32_le(secret.len() as u32);
    src.extend_from_slice(secret);
    src.extend_from_slice(b"retained-next-packet");
    let ptr = src.as_ptr();
    let consumed = 4 + secret.len();
    let mut dst = Vec::new();
    assert_eq!(
        ChunkDecoder::default()
            .decode(&mut src, &mut dst, 1024)
            .unwrap(),
        Some(ChunkInfo::Last(0))
    );
    assert_eq!(dst, secret);
    assert_eq!(&src[..], b"retained-next-packet");
    // The remaining tail keeps the same backing allocation alive.
    let old = unsafe { std::slice::from_raw_parts(ptr, consumed) };
    assert!(
        old.iter().all(|&b| b == 0),
        "consumed plaintext prefix remains accessible in the allocation"
    );
}

#[test]
fn security_compressed_input_prefix_wiped() {
    let secret = b"uncompressed-credential-inside-compressed-envelope";
    let mut src = BytesMut::new();
    src.put_uint_le(secret.len() as u64, 3);
    src.put_u8(0);
    src.put_uint_le(0, 3);
    src.extend_from_slice(secret);
    src.extend_from_slice(b"next-envelope");
    let ptr = src.as_ptr();
    let mut dst = BytesMut::new();
    assert_eq!(
        CompDecoder::Idle.decode(&mut src, &mut dst, 1024).unwrap(),
        Some(ChunkInfo::Last(0))
    );
    assert_eq!(&dst[..], secret);
    assert_eq!(&src[..], b"next-envelope");
    let consumed = unsafe { std::slice::from_raw_parts(ptr, 7 + secret.len()) };
    assert!(consumed.iter().all(|&b| b == 0));
}

#[test]
fn security_compression_clears_plaintext_before_reuse() {
    let mut src = BytesMut::from(&b"secret-private-compression-input"[..]);
    let ptr = src.as_ptr();
    let len = src.len();
    let mut dst = BytesMut::new();
    compress(0, Compression::none(), 1024, &mut src, &mut dst).unwrap();
    assert!(src.is_empty());
    // BytesMut::clear keeps its initialized backing storage allocated.
    assert!(
        unsafe { std::slice::from_raw_parts(ptr, len) }
            .iter()
            .all(|&b| b == 0)
    );
    assert_eq!(&dst[7..], b"secret-private-compression-input");
}

#[test]
fn security_growth_wipes_replaced_codec_storage() {
    let mut dst = BytesMut::with_capacity(32);
    dst.extend_from_slice(&[0x73; 32]);
    watch(&dst);
    let payload = [0x42; 1024];
    assert_eq!(packet_to_chunks(0, &mut &payload[..], &mut dst), 1);
    assert_wiped_before_free();
    assert_eq!(&dst[..32], &[0x73; 32]);
    assert_eq!(&dst[36..], &payload);
}

fn codec() -> CompPacketCodec {
    CompPacketCodec {
        level: Compression::default(),
        comp_seq_id: 0,
        in_buf: BytesMut::from(&b"secret-input"[..]),
        out_buf: BytesMut::from(&b"secret-output"[..]),
        comp_decoder: CompDecoder::Idle,
        plain_codec: PlainPacketCodec::default(),
    }
}

#[test]
fn security_drop_wipes_both_private_codec_buffers() {
    for input in [true, false] {
        let codec = codec();
        watch(if input { &codec.in_buf } else { &codec.out_buf });
        drop(codec);
        assert_wiped_before_free();
    }
}

#[test]
fn security_encode_error_wipes_private_staging() {
    let mut codec = codec();
    assert!(
        codec
            .encode(&mut &b"over-packet-limit"[..], &mut BytesMut::new(), 1)
            .is_err()
    );
    assert_eq!(&codec.in_buf[..], b"secret-input");
    assert!(codec.out_buf.is_empty());
}

#[test]
fn security_failed_decompression_leaves_no_partial_spare_plaintext() {
    let mut src = BytesMut::new();
    compress(
        0,
        Compression::default(),
        1024,
        &mut BytesMut::from(&[0x43_u8; 128][..]),
        &mut src,
    )
    .unwrap();
    // Ask for one byte beyond the actual decompressed packet: read_exact must
    // fail after producing plaintext. The caller's spare storage starts initialized.
    let declared = LittleEndian::read_u24(&src[4..7]);
    LittleEndian::write_u24(&mut src[4..7], declared + 1);
    let mut dst = BytesMut::from(&[0_u8; 256][..]);
    let ptr = dst.as_ptr();
    dst.clear();
    assert!(CompDecoder::Idle.decode(&mut src, &mut dst, 1024).is_err());
    assert!(dst.is_empty());
    assert!(
        unsafe { std::slice::from_raw_parts(ptr, 256) }
            .iter()
            .all(|&b| b == 0)
    );
}

#[test]
fn security_compressed_roundtrip_preserves_levels_and_sequences() {
    for level in [
        Compression::none(),
        Compression::fast(),
        Compression::default(),
        Compression::best(),
    ] {
        let mut encoder = PacketCodec::default();
        let mut decoder = PacketCodec::default();
        encoder.compress(level);
        decoder.compress(level);
        for size in [0, 3, 128 * 1024, 61] {
            let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let mut encoded = BytesMut::new();
            encoder.encode(&mut &payload[..], &mut encoded).unwrap();
            let mut result = Vec::new();
            assert!(decoder.decode(&mut encoded, &mut result).unwrap());
            assert_eq!(result, payload);
            assert!(encoded.is_empty());
        }
    }
}
