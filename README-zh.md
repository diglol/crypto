# Diglol Crypto

[![badge-license]][url-license]
[![badge-latest-release]][url-latest-release]

![badge-platform-android]
![badge-platform-jvm]
![badge-platform-js]
![badge-platform-linux]
![badge-platform-ios]
![badge-platform-tvos]
![badge-platform-watchos]
![badge-platform-windows]

Diglol Crypto for Kotlin Multiplatform.

当前支持:

- random
  - nextInt
  - nextBytes
- [hash][hash]
  - SHA1
  - SHA256
  - SHA384
  - SHA512
- mac
  - [Hmac][hmac] (SHA1, SHA256, SHA384, SHA512)
  - [Poly1305][poly1305]
- pkc
  - Dh
    - [X25519][x25519]
  - Dsa
    - [Ed25519][ed25519]
- kdf
  - [Argon2][argon2]
  - [Pbkdf2][pbkdf2]
- cipher
  - [AesCbc][aescbc] (128, 256)
  - [XChaCha20][xchacha20]
- aead
  - [AesGcm][aesgcm] (128, 256)
  - [XChaCha20Poly1305][xchacha20poly1305]
  - [EncryptThenMac][encryptthenmac]
- otp
  - [HOTP][hotp]
  - [TOTP][totp]
- [siphash][siphash]
  - siphash
  - halfsiphash

### 发布

我们的 [change log](CHANGELOG.md) 有发布历史。

##### Crypto

包含所有的子模块

```gradle
implementation("com.diglol.crypto:crypto:0.1.5")
```

_如果需要依赖子模块，请参考当前支持的加密常量。_

```gradle
implementation("com.diglol.crypto:${submodule}:0.1.5")
```

### License

    Copyright 2022 Diglol

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

[hash]: https://datatracker.ietf.org/doc/html/rfc4634
[hmac]: https://datatracker.ietf.org/doc/html/rfc2104
[poly1305]: https://datatracker.ietf.org/doc/html/rfc7539
[x25519]: https://datatracker.ietf.org/doc/html/rfc7748
[ed25519]: https://datatracker.ietf.org/doc/html/rfc8032
[argon2]: https://datatracker.ietf.org/doc/rfc9106/
[pbkdf2]: https://datatracker.ietf.org/doc/html/rfc6070
[aescbc]: https://datatracker.ietf.org/doc/html/rfc3602
[xchacha20]: https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha-01
[aesgcm]: https://datatracker.ietf.org/doc/html/rfc5288
[xchacha20poly1305]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha
[encryptthenmac]: https://datatracker.ietf.org/doc/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05
[hotp]: https://datatracker.ietf.org/doc/html/rfc4226
[totp]: https://datatracker.ietf.org/doc/html/rfc6238
[siphash]: https://datatracker.ietf.org/doc/rfc9231/

<!-- TAG_VERSION -->
[badge-latest-release]: https://img.shields.io/badge/latest--release-0.1.5-blue.svg?style=flat
[badge-license]: https://img.shields.io/badge/license-Apache%20License%202.0-blue.svg?style=flat
[url-latest-release]: https://github.com/diglol/crypto/releases/latest
[url-license]: https://www.apache.org/licenses/LICENSE-2.0.txt

<!-- TAG_PLATFORMS -->
[badge-platform-android]: http://img.shields.io/badge/-android-6EDB8D.svg?style=flat
[badge-platform-jvm]: http://img.shields.io/badge/-jvm-DB413D.svg?style=flat
[badge-platform-js]: http://img.shields.io/badge/-js-F8DB5D.svg?style=flat
[badge-platform-linux]: http://img.shields.io/badge/-linux-2D3F6C.svg?style=flat
[badge-platform-tvos]: http://img.shields.io/badge/-tvos-808080.svg?style=flat
[badge-platform-ios]: http://img.shields.io/badge/-ios-808080.svg?style=flat
[badge-platform-watchos]: http://img.shields.io/badge/-watchos-C0C0C0.svg?style=flat
[badge-platform-windows]: http://img.shields.io/badge/-windows-4D76CD.svg?style=flat
