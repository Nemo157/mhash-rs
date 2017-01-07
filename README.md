# mhash [![travis-badge][]][travis] [![cargo-badge][]][cargo] ![license-badge][] [![rust-version-badge][]][rust-version]

A Rust implementation of the [multihash][] format as used in [IPFS][].

## Developing

This project uses [clippy][] and denies warnings in CI builds. To ensure your
changes will be accepted please check them with `cargo clippy` (available via
`cargo install clippy` on nightly rust) before submitting a pull request (along
with `cargo test` as usual).

Both the nightly date and clippy version used in CI are pinned in the
`.travis.yml` as clippy sometimes breaks for a few days after a new nightly is
published, feel free to update to a new known good pair anytime as part of a
pull request.

There are a few different features available as they affect the dependencies
that are brought in and are not needed for all cases. Most of the time you
should be able to get away with testing with `cargo test --all-features` to
enable all of them at once. CI builds a few different subsets that are likely to
be enabled together.

## License

Licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you shall be dual licensed as above, without any
additional terms or conditions.

[travis-badge]: https://img.shields.io/travis/mycorrhiza/mhash-rs/master.svg?style=flat-square
[travis]: https://travis-ci.org/mycorrhiza/mhash-rs
[cargo-badge]: https://img.shields.io/crates/v/mhash.svg?style=flat-square
[cargo]: https://crates.io/crates/mhash
[license-badge]: https://img.shields.io/badge/license-MIT/Apache--2.0-lightgray.svg?style=flat-square
[rust-version-badge]: https://img.shields.io/badge/rust-1.13+-blue.svg?style=flat-square
[rust-version]: .travis.yml#L5

[multihash]: https://github.com/multiformats/multihash
[ipfs]: https://ipfs.io
[clippy]: https://github.com/Manishearth/rust-clippy
