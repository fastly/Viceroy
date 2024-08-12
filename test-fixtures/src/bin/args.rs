fn main() {
    let args = Vec::from_iter(std::env::args());

    assert_eq!(args.len(), 1);
    assert_eq!(args[0], "compute-app");
}
