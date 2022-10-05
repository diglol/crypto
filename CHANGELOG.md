# Change Log

## [Unreleased]

## [0.1.3] - 2022-10-05

### Fixed

* Fix ArrayIndexOutOfBoundsException when using `emptyBytes.refTo`.

### Changed

* Replace `dataWithBytes` with `dataWithBytesNoCopy` to avoid allocation.
* Use `as` to convert between `ByteVar` and `UByteVar` because they have the same bit layout.
* Avoid creating `NSData` when using `Aes-Gcm` for encryption.

## [0.1.2] - 2022-09-12

### Fixed

* Error loading Wasm on NodeJs.

## [0.1.1] - 2022-07-18

### Fixed

* Duplicate `BuildConfig`

## [0.1.0] - 2022-07-16

Initial release.
