plugins {
    `java-library`
    `maven-publish`
    signing
}

java {
    withJavadocJar()
    withSourcesJar()
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            versionMapping {
                usage("java-api") {
                    fromResolutionOf("runtimeClasspath")
                }
                usage("java-runtime") {
                    fromResolutionResult()
                }
            }
            pom {
                name.set(project.name)
                description.set(project.name)
                url.set("https://github.com/XhstormR/scanner-plus-plus")
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        name.set("XhstormR")
                        email.set("xhstormr@foxmail.com")
                        url.set("https://github.com/XhstormR")
                    }
                }
                scm {
                    connection.set("scm:git:git@github.com:XhstormR/scanner-plus-plus.git")
                    developerConnection.set("scm:git:git@github.com:XhstormR/scanner-plus-plus.git")
                    url.set("https://github.com/XhstormR/scanner-plus-plus")
                }
            }
        }
    }
    repositories {
        maven {
            name = "LOCAL"
            val releasesRepoUrl = uri(layout.buildDirectory.dir("repos/releases"))
            val snapshotsRepoUrl = uri(layout.buildDirectory.dir("repos/snapshots"))
            url = if (version.toString().endsWith("SNAPSHOT")) snapshotsRepoUrl else releasesRepoUrl
        }
        maven {
            name = "OSSRH"
            val releasesRepoUrl = uri("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/")
            val snapshotsRepoUrl = uri("https://s01.oss.sonatype.org/content/repositories/snapshots/")
            url = if (version.toString().endsWith("SNAPSHOT")) snapshotsRepoUrl else releasesRepoUrl
            credentials {
                runCatching {
                    username = extra["sonatypeUsername"].toString()
                    password = extra["sonatypePassword"].toString()
                }.onFailure {
                    logger.warn(it.message)
                }
            }
        }
    }
}

signing {
    sign(publishing.publications["mavenJava"])
}
