plugins {
    `java-library`
    kotlin("jvm")
    kotlin("plugin.serialization")
    publish
}

dependencies {
    implementation(kotlin("stdlib-jdk8"))

    compileOnly("net.portswigger.burp.extender:burp-extender-api:+")

    implementation("org.jetbrains.kotlinx:kotlinx-serialization-hocon:+")

    implementation("io.ktor:ktor-client-cio:+")
    implementation("io.ktor:ktor-client-content-negotiation:+")
    implementation("io.ktor:ktor-serialization-kotlinx-json:+")

    implementation("org.springframework:spring-expression:5.3.19")

    testImplementation("org.junit.jupiter:junit-jupiter:+")
    testImplementation("org.mockito:mockito-core:+")
    testImplementation("org.mockito.kotlin:mockito-kotlin:+")
    testImplementation("net.portswigger.burp.extender:burp-extender-api:+")
    testImplementation(rootProject.files("./libs/albinowaxUtils-all.jar"))
}

tasks {
    withType<Jar> {
        duplicatesStrategy = DuplicatesStrategy.EXCLUDE
        from(configurations.runtimeClasspath.get().map { zipTree(it) })
        exclude("**/*.kotlin_module")
        exclude("**/*.kotlin_metadata")
        exclude("**/*.kotlin_builtins")
    }
}
