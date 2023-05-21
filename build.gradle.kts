import com.android.build.api.dsl.CommonExtension
import com.android.build.gradle.AppPlugin
import com.android.build.gradle.LibraryExtension
import com.android.build.gradle.LibraryPlugin
import com.android.build.gradle.internal.dsl.BaseAppModuleExtension
import com.vanniktech.maven.publish.MavenPublishBaseExtension
import com.vanniktech.maven.publish.SonatypeHost
import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent
import org.jetbrains.dokka.gradle.DokkaMultiModuleTask
import org.jetbrains.dokka.gradle.DokkaTaskPartial
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.targets.js.yarn.YarnLockMismatchReport
import org.jetbrains.kotlin.gradle.targets.js.yarn.YarnPlugin
import org.jetbrains.kotlin.gradle.targets.js.yarn.YarnRootExtension
import org.jetbrains.kotlin.gradle.tasks.KotlinJvmCompile

buildscript {
  repositories {
    gradlePluginPortal()
    mavenCentral()
    google()
  }
  dependencies {
    classpath(libs.kotlin.gradle.plugin)
    classpath(libs.kotlin.allopen)
    classpath(libs.android.gradle.plugin)
    // classpath(libs.cklib.gradle.plugin) // TODO https://github.com/touchlab/cklib/pull/11
    classpath(files("local-plugins/cklib-plugin-0.2.4-fix.jar"))
    classpath(libs.dokka.gradle.plugin)
    classpath(libs.mavenPublish.gradle.plugin)
    classpath(libs.benchmark.gradle.plugin)
  }
}

allprojects {
  group = "com.diglol.crypto"
  version = "0.2.0-SNAPSHOT"

  repositories {
    mavenCentral()
    google()
  }
}

subprojects {
  fun CommonExtension<*, *, *, *>.applyAndroid() {
    lint {
      textReport = true
      textOutput = file("stdout")
      lintConfig = rootProject.file("lint.xml")

      checkDependencies = true
      checkTestSources = false
      explainIssues = false

      checkReleaseBuilds = true
    }

    compileSdk = 33
    defaultConfig {
      minSdk = 21
    }

    compileOptions {
      sourceCompatibility = JavaVersion.VERSION_1_8
      targetCompatibility = JavaVersion.VERSION_1_8
    }
  }

  plugins.withType<LibraryPlugin>().configureEach {
    extensions.configure<LibraryExtension> { applyAndroid() }
  }

  plugins.withType<AppPlugin>().configureEach {
    extensions.configure<BaseAppModuleExtension> {
      applyAndroid()
      defaultConfig.targetSdk = 33
    }
  }

  tasks.withType<JavaCompile>().configureEach {
    sourceCompatibility = JavaVersion.VERSION_1_8.toString()
    targetCompatibility = JavaVersion.VERSION_1_8.toString()
  }

  tasks.withType<KotlinJvmCompile>().configureEach {
    compilerOptions {
      jvmTarget.set(JvmTarget.JVM_1_8)
      freeCompilerArgs.addAll("-Xjvm-default=all")
    }
  }

  tasks.withType(Test::class).configureEach {
    testLogging {
      if (System.getenv("CI") == "true") {
        events = setOf(TestLogEvent.FAILED, TestLogEvent.SKIPPED, TestLogEvent.PASSED)
      }
      exceptionFormat = TestExceptionFormat.FULL
    }
  }

  tasks.withType<AbstractArchiveTask>().configureEach {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
  }

  normalization {
    runtimeClasspath {
      metaInf {
        ignoreAttribute("Bnd-LastModified")
      }
    }
  }
}

apply(plugin = "org.jetbrains.dokka")

tasks.withType<DokkaMultiModuleTask> {
  outputDirectory.set(rootProject.file("build/dokka/html"))
  failOnWarning.set(true)
}

// TODO remove if https://youtrack.jetbrains.com/issue/KT-55701 provides a better
rootProject.plugins.withType(YarnPlugin::class.java) {
  rootProject.the<YarnRootExtension>().yarnLockMismatchReport =
    YarnLockMismatchReport.WARNING // NONE | FAIL
  rootProject.the<YarnRootExtension>().reportNewYarnLock = false // true
  rootProject.the<YarnRootExtension>().yarnLockAutoReplace = false // true
}

allprojects {
  tasks.withType<DokkaTaskPartial>().configureEach {
    if (project.name == "crypto") {
      return@configureEach
    }
    dokkaSourceSets.configureEach {
      reportUndocumented.set(false)
      skipDeprecated.set(true)
      jdkVersion.set(8)
      noAndroidSdkLink.set(true)

      perPackageOption {
        matchingRegex.set("diglol\\.crypto\\.internal\\.*")
        suppress.set(true)
      }
    }
  }

  plugins.withId("com.vanniktech.maven.publish.base") {
    configure<PublishingExtension> {
      repositories {
        maven {
          name = "testMaven"
          url = file("${rootProject.buildDir}/testMaven").toURI()
        }
      }
    }
    configure<MavenPublishBaseExtension> {
      publishToMavenCentral(SonatypeHost.S01)
      signAllPublications()
      pom {
        description.set("Diglol Crypto for Kotlin Multiplatform.")
        name.set(project.name)
        url.set("https://github.com/diglol/crypto/")
        licenses {
          license {
            name.set("The Apache Software License, Version 2.0")
            url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
            distribution.set("repo")
          }
        }
        developers {
          developer {
            id.set("diglol")
            name.set("Diglol")
            url.set("https://github.com/diglol/")
          }
        }
        scm {
          url.set("https://github.com/diglol/crypto/")
          connection.set("scm:git:https://github.com/diglol/crypto.git")
          developerConnection.set("scm:git:ssh://git@github.com/diglol/crypto.git")
        }
      }
    }
  }
}

