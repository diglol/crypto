import co.touchlab.cklib.gradle.CompileToBitcode.Language.C
import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.KotlinMultiplatform
import com.vanniktech.maven.publish.MavenPublishBaseExtension
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget

plugins {
  kotlin("multiplatform")
  id("com.android.library")
  id("org.jetbrains.dokka")
  id("com.vanniktech.maven.publish.base")
  id("co.touchlab.cklib")
}

kotlin {
  android {
    publishLibraryVariants("release")
  }
  jvm()
  js(IR) {
    browser()
    nodejs()
  }

  macosX64()
  macosArm64()
  iosX64()
  iosArm64()
  iosSimulatorArm64()
  watchosArm32()
  watchosArm64()
  watchosSimulatorArm64()
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
        api(libs.kotlinx.coroutines.core)
        api(projects.common)
        api(projects.mac)
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
      dependencies {
        api(libs.argon2.jvm)
      }
    }
    val jvmTest by sourceSets.getting {
      dependsOn(jvmMain)
      dependsOn(commonJvmTest)
    }

    val androidMain by sourceSets.getting {
      dependsOn(commonJvmMain)
      dependencies {
        api(libs.argon2.android)
      }
    }
    val androidUnitTest by sourceSets.getting {
      dependsOn(androidMain)
      dependsOn(commonJvmTest)
    }

    val jsMain by sourceSets.getting {
      dependencies {
        api(libs.diglol.encoding)
        api(npm("wasm-feature-detect", "1.5.0"))
        api(npm("argon2-browser", "1.18.0"))
        api(npm("base64-loader", "1.0.0"))
      }
    }
    val jsTest by sourceSets.getting

    val darwinMain by sourceSets.creating {
      dependsOn(commonMain)
    }
    val darwinTest by sourceSets.creating {
      dependsOn(commonTest)
    }

    targets.withType<KotlinNativeTarget>().all {
      val main by compilations.getting
      val test by compilations.getting

      main.cinterops {
        create("kdf") {
          includeDirs("$projectDir/argon2")
          compilerOpts("-DNS_FORMAT_ARGUMENT(A)=", "-D_Nullable_result=_Nullable")
        }
      }

      main.defaultSourceSet.dependsOn(
        when {
          konanTarget.family.isAppleFamily -> darwinMain
          else -> TODO("Not yet implemented")
        }
      )

      test.defaultSourceSet.dependsOn(
        if (konanTarget.family.isAppleFamily) {
          darwinTest
        } else {
          commonTest
        }
      )
    }
  }
}

cklib {
  config.kotlinVersion = libs.versions.kotlin.get()
  create("kdf") {
    language = C
    srcDirs = project.files(file("argon2"))
    compilerArgs.addAll(
      listOf("-DKONAN_MI_MALLOC=1", "-DNS_FORMAT_ARGUMENT(A)=", "-D_Nullable_result=_Nullable")
    )
  }
}

android {
  namespace = "diglol.crypto.kdf"

  defaultConfig {
    consumerProguardFiles("proguard-rules.pro")
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
