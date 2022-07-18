import com.android.build.gradle.BaseExtension
import com.vanniktech.maven.publish.MavenPublishBaseExtension
import com.vanniktech.maven.publish.SonatypeHost
import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent
import org.jetbrains.dokka.gradle.DokkaMultiModuleTask
import org.jetbrains.dokka.gradle.DokkaTaskPartial

buildscript {
  repositories {
    gradlePluginPortal()
    mavenCentral()
    google()
  }
  dependencies {
    classpath(libs.kotlin.gradle.plugin)
    classpath(libs.android.gradle.plugin)
    classpath(libs.cklib.gradle.plugin)
    classpath(libs.dokka.gradle.plugin)
    classpath(libs.mavenPublish.gradle.plugin)
    classpath(libs.benchmark.gradle.plugin)
  }
}

allprojects {
  group = "com.diglol.crypto"
  version = "0.1.1"

  repositories {
    mavenCentral()
    google()
  }
}

subprojects {
  plugins.withId("com.android.library") {
    extensions.configure<BaseExtension> {
      lintOptions {
        textReport = true
        textOutput("stdout")
        lintConfig = rootProject.file("lint.xml")

        isCheckDependencies = true
        isCheckTestSources = false
        isExplainIssues = false

        isCheckReleaseBuilds = false
      }
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
}

apply(plugin = "org.jetbrains.dokka")

tasks.withType<DokkaMultiModuleTask> {
  outputDirectory.set(rootProject.file("build/dokka/html"))
  failOnWarning.set(true)
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

