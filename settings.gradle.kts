rootProject.name = "crypto-root"

include(":common")
include(":random")
include(":hash")
include(":mac")
// TODO Error with cklib on Windows
if (!System.getProperty("os.name").startsWith("Windows")) {
  include(":pkc")
  include(":kdf")
  include(":aead")
  include(":crypto")
  include(":benchmark")
  include(":samples")
}
include(":cipher")
include(":otp")

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")
