/*
 * Copyright 2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

configurations {
    register("intellij") {
        resolutionStrategy.disableDependencyVerification()
    }
    register("metadataTool") {
        resolutionStrategy.disableDependencyVerification()
    }
}

repositories {
    maven {
        name = "JetBrains IJ releases"
        url = uri("https://www.jetbrains.com/intellij-repository/releases")
        content {
            includeGroup("com.jetbrains.intellij.idea")
        }
    }
    maven {
        name = "JetBrains shared index tool releases"
        url = uri("https://packages.jetbrains.team/maven/p/ij/intellij-shared-indexes-public")
        content {
            includeGroup("com.jetbrains.intellij.indexing.shared")
        }
    }
}

dependencies {
    "intellij"("com.jetbrains.intellij.idea:ideaIU:2021.3.2@zip")
    "metadataTool"("com.jetbrains.intellij.indexing.shared:cdn-layout-tool:0.8.65@zip")
}

//tasks.create("beezlebub")

tasks {
    val unzipIntelliJ by registering(Sync::class) {
        dependsOn(configurations.named("intellij"))
        // Represents the contents of the "intellij" configuration as a zipTree. Callable prevents eager evaluation.
        from(Callable { configurations.named("intellij").get().map { zipTree(it) } })
        into(project.layout.buildDirectory.file("$name/intellij"))
    }
    val runDumpSharedIndex by registering(Exec::class) {
        dependsOn(unzipIntelliJ)
        commandLine(project.layout.buildDirectory.dir("unzipIntelliJ/intellij/bin").get().asFile.absolutePath + "/idea.sh", "dump-shared-index", "project")
        //workingDir(unzipIntelliJ.map { it.destinationDir })
//        commandLine(project.layout.buildDirectory.dir("intellij/bin"))
    }
}
