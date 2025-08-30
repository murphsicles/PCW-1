use criterion::{criterion_group, criterion_main, Criterion};
use pcw_protocol::scope::Scope;
use pcw_protocol::split::bounded_split;

fn bench_split(c: &mut Criterion) {
    let scope = Scope::new([0;32], [0;32]);
    c.bench_function("bounded_split N~100", |b| b.iter(|| bounded_split(&scope, 1_000_000, 100, 10_000)));
}

criterion_group!(benches, bench_split);
criterion_main!(benches);
