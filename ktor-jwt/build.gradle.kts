plugins {
    id("org.jetbrains.kotlin.plugin.serialization")
}

val serialization_version: String by project.extra

kotlin {
    sourceSets {
        commonMain {
            dependencies {
                api(project(":ktor-utils"))
                api("org.jetbrains.kotlinx:kotlinx-serialization-json:$serialization_version")
            }
        }
    }
}
