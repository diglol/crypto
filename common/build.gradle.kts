import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.KotlinMultiplatform
import com.vanniktech.maven.publish.MavenPublishBaseExtension
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import org.jetbrains.kotlin.konan.target.Family.LINUX
import org.jetbrains.kotlin.konan.target.Family.MINGW

plugins {
  kotlin("multiplatform")
  id("com.android.library")
  id("org.jetbrains.dokka")
  id("com.vanniktech.maven.publish.base")
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

  mingwX64()
  linuxX64()

  sourceSets {
    all {
      languageSettings.optIn("kotlin.RequiresOptIn")
    }
    matching { it.name.endsWith("Test") }.all {
      languageSettings {
        optIn("kotlin.RequiresOptIn")
      }
    }

    val commonMain by sourceSets.getting
    val commonTest by sourceSets.getting {
      dependencies {
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
    val androidUnitTest by sourceSets.getting {
      dependsOn(androidMain)
      dependsOn(commonJvmTest)
    }

    val jsMain by sourceSets.getting
    val jsTest by sourceSets.getting

    val nativeMain by sourceSets.creating
    nativeMain.dependsOn(commonMain)

    val darwinMain by sourceSets.creating {
      dependsOn(nativeMain)
    }
    val darwinTest by sourceSets.creating {
      dependsOn(commonTest)
    }

    val linuxMain by sourceSets.creating {
      dependsOn(nativeMain)
    }

    val mingwMain by sourceSets.creating {
      dependsOn(nativeMain)
    }

    targets.withType<KotlinNativeTarget>().all {
      val main by compilations.getting
      val test by compilations.getting

      main.defaultSourceSet.dependsOn(
        when {
          konanTarget.family.isAppleFamily -> darwinMain
          konanTarget.family == LINUX -> linuxMain
          konanTarget.family == MINGW -> mingwMain
          else -> nativeMain
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

android {
  namespace = "diglol.crypto.common"

  compileSdk = libs.versions.compileSdk.get().toInt()
  defaultConfig {
    minSdk = libs.versions.minSdk.get().toInt()

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
