use blocklist_core::encode::encode_domains;
use blocklist_core::{Blocklist, CompiledList, Overlay};
use criterion::{Criterion, criterion_group, criterion_main};

fn fixture() -> Blocklist {
    let mut domains = vec![String::from("example.com"), String::from("tracker.test")];
    domains.extend((0..10_000).map(|index| format!("blocked-{index}.fixture.test")));
    let bytes = encode_domains(domains.iter().map(String::as_str)).expect("fixture encodes");
    Blocklist::new(
        vec![CompiledList::from_bytes("fixture", bytes)],
        Overlay::default(),
    )
}

fn lookup(c: &mut Criterion) {
    let blocklist = fixture();

    c.bench_function("lookup/hit/4-label", |bench| {
        bench.iter(|| blocklist.matches("track.ads.example.com"));
    });
    c.bench_function("lookup/miss/4-label", |bench| {
        bench.iter(|| blocklist.matches("safe.cdn.example.net"));
    });
    c.bench_function("lookup/miss/8-label", |bench| {
        bench.iter(|| blocklist.matches("a.b.c.d.e.f.g.example.net"));
    });
    c.bench_function("lookup/throughput", |bench| {
        let queries = include_str!("queries.txt").lines().collect::<Vec<_>>();
        bench.iter(|| {
            for query in &queries {
                let _ = blocklist.matches(query);
            }
        });
    });
    c.bench_function("cold-load", |bench| {
        let bytes = blocklist.compiled_lists()[0].bytes().to_vec();
        bench.iter(|| {
            let list = CompiledList::from_bytes("fixture", bytes.clone());
            list.matches("track.ads.example.com")
        });
    });
}

criterion_group!(benches, lookup);
criterion_main!(benches);
