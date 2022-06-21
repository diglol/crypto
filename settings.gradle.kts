rootProject.name = "crypto-root"

include(":common")
include(":random")
include(":hash")
include(":mac")
include(":pkc")
include(":kdf")
include(":cipher")
include(":aead")
include(":otp")
include(":crypto")
include(":benchmark")
include(":samples")

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")
