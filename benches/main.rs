use criterion::{Criterion, criterion_group, criterion_main};
use pcw_protocol::scope::Scope;
use pcw_protocol::split::bounded_split;

fn bench_split(c: &mut Criterion) {
    let scope = Scope::new([0; 32], [0; 32]);
    c.bench_function("bounded_split N~100", |b| {
        b.iter(|| bounded_split(&scope, 1_000_000, 100, 10_000))
    });
}

fn bench_derive_scalar(c: &mut Criterion) {
    let scope = Scope::new([0; 32], [0; 32]);
    c.bench_function("derive_scalar 1000 times", |b| {
        b.iter(|| (0..1000).for_each(|i| derive_scalar(&scope, "recv", i).unwrap()))
    });
}

criterion_group!(benches, bench_split, bench_derive_scalar);
criterion_main!(benches);
