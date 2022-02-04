import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    idea
    val kotlinVersion = "1.6.10"
    kotlin("jvm") version kotlinVersion apply false
    kotlin("plugin.serialization") version kotlinVersion apply false
    id("org.jlleitschuh.gradle.ktlint") version "10.2.1"
    id("io.github.gradle-nexus.publish-plugin") version "1.1.0"
}

nexusPublishing {
    repositories {
        sonatype {
            nexusUrl.set(uri("https://s01.oss.sonatype.org/service/local/"))
            snapshotRepositoryUrl.set(uri("https://s01.oss.sonatype.org/content/repositories/snapshots/"))
        }
    }
}

allprojects {

    group = "io.github.xhstormr.burp-extender"
    version = "1.0-SNAPSHOT"

    repositories {
        maven("https://mirrors.huaweicloud.com/repository/maven")
        maven("https://maven.aliyun.com/repository/public")
    }

    apply {
        plugin("org.jlleitschuh.gradle.ktlint")
    }

    tasks {
        withType<KotlinCompile> {
            kotlinOptions {
                jvmTarget = "11"
                freeCompilerArgs = listOf("-Xjsr305=strict", "-Xjvm-default=all")
            }
        }

        withType<JavaCompile> {
            with(options) {
                encoding = Charsets.UTF_8.name()
                isFork = true
                isIncremental = true
                release.set(11)
            }
        }
    }
}

tasks {
    register<Delete>("clean") {
        delete(rootProject.buildDir)
    }

    withType<Wrapper> {
        gradleVersion = "7.4"
        distributionType = Wrapper.DistributionType.ALL
    }
}
