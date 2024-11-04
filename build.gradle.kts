// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    id("com.android.application") version "8.7.2" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    id("io.gitlab.arturbosch.detekt") version "1.23.7" apply false
    id("com.google.devtools.ksp") version "2.0.21-1.0.25" apply false
    id("org.jetbrains.kotlin.plugin.serialization") version "2.0.21" apply false
    id("com.google.dagger.hilt.android") version "2.52" apply false
}
