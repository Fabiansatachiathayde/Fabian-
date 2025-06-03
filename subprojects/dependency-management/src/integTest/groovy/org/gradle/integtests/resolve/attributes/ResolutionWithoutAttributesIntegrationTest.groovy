/*
 * Copyright 2021 the original author or authors.
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

package org.gradle.integtests.resolve.attributes

import org.gradle.integtests.fixtures.AbstractIntegrationSpec

class ResolutionWithoutAttributesIntegrationTest extends AbstractIntegrationSpec {

    def "resolution of a configuration without attributes is deprecated in jvm ecosystem"() {
        when:
        buildFile << """
            plugins {
                id("$jvmPlugin")
            }

            configurations {
                withoutAttributes
            }

            tasks.register("resolveWithoutAttributes") {
                doLast { configurations.withoutAttributes.files.forEach { println(it.name) } }
            }
        """

        then:
        executer.expectDocumentedDeprecationWarning("Resolving a configuration without attributes (configurationName=withoutAttributes) has been deprecated. This will fail with an error in Gradle 8.0. Consult the upgrading guide for further information: https://docs.gradle.org/current/userguide/upgrading_version_7.html#resolving_configuration_without_attributes")
        succeeds("resolveWithoutAttributes")

        where:
        jvmPlugin << ["java", "java-library", "java-base", "java-platform", "groovy", "scala"]
    }

    def "configuration can be resolved without attributes"() {
        when:
        buildFile << """
            configurations {
                withoutAttributes
            }

            tasks.register("resolveWithoutAttributes") {
                doLast { configurations.withoutAttributes.files.forEach { println(it.name) } }
            }
        """

        then:
        succeeds("resolveWithoutAttributes")
    }
}
