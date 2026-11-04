import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "2.2.20"
    id("com.gradleup.shadow") version "8.3.9"
}

group = "io.sectiv"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    // Provided by Burp at runtime. Never bundle this jar.
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.7")

    implementation("com.fasterxml.jackson.core:jackson-databind:2.19.2")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.19.2")

    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.13.4")
    testImplementation("net.portswigger.burp.extensions:montoya-api:2026.7")
}

kotlin {
    jvmToolchain(21)
}

tasks.withType<KotlinCompile>().configureEach {
    compilerOptions {
        freeCompilerArgs.add("-Xjvm-default=all")
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}

tasks.shadowJar {
    archiveBaseName.set("sectiv")
    archiveClassifier.set("")
    archiveVersion.set(project.version.toString())

    // Avoid clashing with the copy of Jackson Burp or another extension may load.
    relocate("com.fasterxml.jackson", "io.sectiv.shaded.jackson")

    mergeServiceFiles()

    manifest {
        attributes(
            "Implementation-Title" to "Sectiv",
            "Implementation-Version" to project.version,
            "Implementation-Vendor" to "Sectiv",
            "Extension-Class" to "io.sectiv.burp.SectivExtension"
        )
    }
}

tasks.build {
    dependsOn(tasks.shadowJar)
}
