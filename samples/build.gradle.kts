plugins {
  kotlin("multiplatform")
  application
}

application {
  mainClass.set("diglol.crypto.samples.Samples")
}

kotlin {
  jvm {
    withJava()
  }

  sourceSets {
    commonMain {
      dependencies {
        implementation(projects.crypto)
        implementation(libs.diglol.encoding)
      }
    }
  }
}
