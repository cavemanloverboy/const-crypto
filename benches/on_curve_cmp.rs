use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn decompress(c: &mut Criterion) {
    let mut g = c.benchmark_group("on_curve");
    g.throughput(criterion::Throughput::Elements(1));

    // Some input
    let bytes = rand::random::<[u8; 32]>();

    // Unsafe
    g.bench_function("unsafe-decompress", |b| {
        b.iter(|| {
            black_box(const_crypto::ed25519::crypto_unsafe_is_on_curve(black_box(
                &bytes,
            )))
        })
    });

    // Safe
    g.bench_function("safe-decompress", |b| {
        b.iter(|| black_box(safe_is_on_curve(black_box(&bytes))))
    });
}

fn safe_is_on_curve(key: &[u8; 32]) -> bool {
    curve25519_dalek::edwards::CompressedEdwardsY::from_slice(key.as_ref())
        .unwrap()
        .decompress()
        .is_some()
}

criterion_group!(decompression, decompress);
criterion_main!(decompression);
