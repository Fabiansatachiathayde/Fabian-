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

plugins {
    id("gradlebuild.build-logic.kotlin-dsl-gradle-plugin")
}

description = "Provides plugin to generate and publish IntelliJ shared indexes of the gradle/gradle build"

//configurations {
//  register("intellij")
//  register("metadataTool")
//}
//
//dependencies {
//    "intellij"("com.jetbrains.intellij.idea:ideaIU:2021.3.2@zip")
//    "metadataTool"("com.jetbrains.intellij.indexing.shared:cdn-layout-tool:0.8.65@zip")
//}
//
//tasks.register<Sync>("unzipIntelliJ") {
//    from(configurations.named("intellij")) //.get().singleFile
//    into(temporaryDir)
//}
//
//tasks.create("beezlebub")
//
//
//
////tasks {
////    val unzipIntelliJ by creating(Sync::class) {
////        from(configurations.named("intellij"))
////        into(temporaryDir)
////    }
////}
