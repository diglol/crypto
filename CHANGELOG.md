# Change Log

## [Unreleased]

### Added

* Siphash implementation
* Halfsiphash implementation

## [0.1.5] - 2023-08-16

### Changed

* Remove the minimum length limit for Hmac - Key (#82)

### Fixed

* Fix StringIndexOutOfBoundsException when converting a string to Otp (#83)

## [0.1.4] - 2023-02-25

### Changed

* Provide friendly api for Jvm (#26)

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
