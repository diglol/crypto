import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget

plugins {
  kotlin("multiplatform")
  kotlin("plugin.allopen") version "1.6.21"
  id("org.jetbrains.kotlinx.benchmark")
}

allOpen {
  annotation("org.openjdk.jmh.annotations.State")
}

kotlin {
  jvm()
  js("jsIr", IR) {
    nodejs()
  }
  js("js", LEGACY) {
    nodejs()
  }

  macosX64()
  macosArm64()

  sourceSets {
    all {
      languageSettings.optIn("kotlin.RequiresOptIn")
    }

    val commonMain by sourceSets.getting {
      dependencies {
        implementation(projects.crypto)
        implementation(libs.kotlinx.coroutines.test)
        implementation(libs.benchmark.runtime)
      }
    }

    val jvmMain by sourceSets.getting {
      dependsOn(commonMain)
      dependencies {
        api(libs.jmh.core)
      }
    }

    val jsMain by sourceSets.getting
    val jsIrMain by sourceSets.getting {
      dependsOn(jsMain)
    }

    val nativeMain by sourceSets.creating {
      dependsOn(commonMain)
    }

    val darwinMain by sourceSets.creating {
      dependsOn(nativeMain)
    }

    targets.withType<KotlinNativeTarget>().all {
      val main by compilations.getting

      main.defaultSourceSet.dependsOn(
        when {
          konanTarget.family.isAppleFamily -> darwinMain
          else -> nativeMain
        }
      )
    }
  }
}

benchmark {
  configurations {
    getByName("main") {
      iterations = 5
      iterationTime = 1
      advanced("jvmForks", 1)
      advanced("nativeGCAfterIteration", true)
      advanced("nativeFork", "perBenchmark")
      reportFormat = "text"
    }

    targets {
      register("jvm")
      register("jsIr")
      register("js")
      register("macosX64")
      register("macosArm64")
    }
  }
}
