import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.KotlinMultiplatform
import com.vanniktech.maven.publish.MavenPublishBaseExtension
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget

plugins {
  kotlin("multiplatform")
  kotlin("native.cocoapods")
  id("com.android.library")
  id("org.jetbrains.dokka")
  id("com.vanniktech.maven.publish.base")
}

kotlin {
  android {
    publishLibraryVariants("release")
  }
  jvm()
  js(BOTH) {
    browser()
  }

  cocoapods {
    summary = "Crypto Aead"
    homepage = "https://github.com/diglol/crypto"

    pod("AesGcm") {
      source = git("https://github.com/robxyy/AesGcm.git") {
        branch = "trunk"
      }
    }
  }

  macosX64()
  macosArm64()
  iosX64()
  iosArm64()
  iosArm32()
  iosSimulatorArm64()
  watchosArm32()
  watchosArm64()
  watchosSimulatorArm64()
  watchosX86()
  watchosX64()
  tvosArm64()
  tvosSimulatorArm64()
  tvosX64()

  sourceSets {
    all {
      languageSettings.optIn("kotlin.RequiresOptIn")
    }
    matching { it.name.endsWith("Test") }.all {
      languageSettings {
        optIn("kotlin.RequiresOptIn")
      }
    }

    val commonMain by sourceSets.getting {
      dependencies {
        api(projects.common)
        api(projects.mac)
        api(projects.random)
        api(projects.cipher)
      }
    }
    val commonTest by sourceSets.getting {
      dependencies {
        implementation(libs.kotlinx.coroutines.test)
        implementation(libs.diglol.encoding)
        implementation(kotlin("test"))
      }
    }

    val commonJvmMain by sourceSets.creating {
      dependsOn(commonMain)
    }
    val commonJvmTest by sourceSets.creating {
      dependsOn(commonJvmMain)
      dependsOn(commonTest)
    }

    val jvmMain by sourceSets.getting {
      dependsOn(commonJvmMain)
    }
    val jvmTest by sourceSets.getting {
      dependsOn(jvmMain)
      dependsOn(commonJvmTest)
    }

    val androidMain by sourceSets.getting {
      dependsOn(commonJvmMain)
    }
    val androidTest by sourceSets.getting {
      dependsOn(androidMain)
      dependsOn(commonJvmTest)
    }

    val jsMain by sourceSets.getting
    val jsTest by sourceSets.getting

    val darwinMain by sourceSets.creating {
      dependsOn(commonMain)
    }
    val darwinTest by sourceSets.creating {
      dependsOn(commonTest)
    }

    targets.withType<KotlinNativeTarget>().all {
      val mainSourceSet = compilations.getByName("main").defaultSourceSet
      val testSourceSet = compilations.getByName("test").defaultSourceSet

      mainSourceSet.dependsOn(
        when {
          konanTarget.family.isAppleFamily -> darwinMain
          else -> TODO("Not yet implemented")
        }
      )

      testSourceSet.dependsOn(
        if (konanTarget.family.isAppleFamily) {
          darwinTest
        } else {
          commonTest
        }
      )
    }
  }
}

android {
  compileSdk = libs.versions.compileSdk.get().toInt()
  defaultConfig {
    minSdk = libs.versions.minSdk.get().toInt()

    consumerProguardFiles("proguard-rules.pro")
  }

  val main by sourceSets.getting {
    manifest.srcFile("src/androidMain/AndroidManifest.xml")
  }

  testOptions {
    unitTests.isReturnDefaultValues = true
  }
}

dependencies {
  androidTestImplementation(libs.junit)
  androidTestImplementation(libs.androidx.test.runner)
}

configure<MavenPublishBaseExtension> {
  configure(
    KotlinMultiplatform(
      javadocJar = JavadocJar.Dokka("dokkaGfm")
    )
  )
}
