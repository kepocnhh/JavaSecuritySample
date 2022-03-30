repositories.mavenCentral()

plugins {
    id("application")
    id("org.jetbrains.kotlin.jvm")
}

dependencies {
    // todo
}

application {
    mainClass.set("test.java.security.AppKt")
}

val jvmTarget = "1.8"

tasks.getByName<JavaCompile>("compileJava") {
    targetCompatibility = jvmTarget
}

tasks.getByName<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>("compileKotlin") {
    kotlinOptions.jvmTarget = jvmTarget
}
