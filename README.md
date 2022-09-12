# Diglol Crypto

Diglol Crypto for Kotlin Multiplatform.

Currently supported:

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

### Releases

Our [change log](CHANGELOG.md) has release history.

##### Crypto

Include all submodules.

```gradle
implementation("com.diglol.crypto:crypto:0.1.2")
```

_If you need to depend on a submodule, please refer to the currently supported cryptographic constants._

```gradle
implementation("com.diglol.crypto:${submodule}:0.1.2")
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
