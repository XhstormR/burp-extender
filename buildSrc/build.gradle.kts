plugins {
    `kotlin-dsl`
}

repositories {
    maven("https://mirrors.huaweicloud.com/repository/maven")
    maven("https://maven.aliyun.com/repository/gradle-plugin")
    gradlePluginPortal()
}

dependencies {
}

fun plugin(id: String, version: String) = "$id:$id.gradle.plugin:$version"
