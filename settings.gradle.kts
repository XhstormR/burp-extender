rootProject.name = "scanner-plus-plus"

include("core")

pluginManagement {
    repositories {
        maven("https://mirrors.huaweicloud.com/repository/maven")
        maven("https://maven.aliyun.com/repository/gradle-plugin")
    }
}
