use criterion::{black_box, Criterion, criterion_group, criterion_main};
use pcw_protocol::scope::Scope;
use pcw_protocol::split::bounded_split;

fn bench_split(c: &mut Criterion) {
    let scope = Scope::new([1u8; 32], [2u8; 32]).expect("Valid scope");
    c.bench_function("bounded_split N~100", |b| {
        b.iter(|| bounded_split(&scope, 1_000_000, 100, 10_000))
    });
}

fn bench_derive_scalar(c: &mut Criterion) {
    let scope = Scope::new([1u8; 32], [2u8; 32]).expect("Valid scope");
    c.bench_function("derive_scalar 1000 times", |b| {
        b.iter(|| {
            for i in 0..1000 {
                black_box(scope.derive_scalar("recv", i).unwrap());
            }
        })
    });
}

criterion_group!(benches, bench_split, bench_derive_scalar);
criterion_main!(benches);
