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

package org.gradle.integtests.resolve.derived

import org.gradle.integtests.fixtures.AbstractIntegrationSpec

class AmbiguousVariantSelectionTest extends AbstractIntegrationSpec {

    def setup() {
        multiProjectBuild('root', ['producer', 'consumer']) {
            buildFile << '''
            '''

            file('producer/build.gradle') << """
                group = 'org.test'
                version = '1.0'

                configurations {
                    def usage = Attribute.of('usage', String)
                    def libraryelements = Attribute.of('libraryelements', String)

                    fooElements {
                        canBeResolved = false
                        canBeConsumed = true
                        attributes {
                            attribute(usage, 'java-api')
                            attribute(libraryelements, 'classes')
                        }

                        outgoing {
                            artifact(layout.projectDirectory.dir(project.name + '-foo'))
                        }
                    }

                    barElements {
                        canBeResolved = false
                        canBeConsumed = true
                        attributes {
                            attribute(usage, 'java-runtime')
                            attribute(libraryelements, 'jar')
                        }

                        outgoing {
                            artifact(layout.projectDirectory.file(project.name + '-bar.jar'))
                        }
                    }
                }
            """

            file('consumer/build.gradle') << """

                def usage = Attribute.of('usage', String)
                def libraryelements = Attribute.of('libraryelements', String)

                class AmbiguousCompatibilityRule implements AttributeCompatibilityRule<String> {
                    void execute(CompatibilityCheckDetails<String> details) {
                        details.compatible()
                    }
                }

                dependencies.attributesSchema {
                    attribute(usage) {
                        compatibilityRules.add(AmbiguousCompatibilityRule)
                    }
                    attribute(libraryelements) {
                        compatibilityRules.add(AmbiguousCompatibilityRule)
                    }
                }

                configurations {
                    producerArtifacts {
                        attributes {
                            attribute(usage, 'java-api') // adjust these to select a different variant
                            attribute(libraryelements, 'jar') // adjust these to select a different variant
                        }
                    }
                }

                dependencies {
                    producerArtifacts project(':producer')
                }

                abstract class Resolve extends DefaultTask {
                    @InputFiles
                    abstract ConfigurableFileCollection getArtifacts()
                    @Internal
                    List<String> expectations = []
                    @TaskAction
                    void assertThat() {
                        logger.lifecycle 'Found files: {}', artifacts.files*.name
                        assert artifacts.files*.name == expectations
                    }
                }

                tasks.register('resolve', Resolve) {
                    artifacts.from(configurations.producerArtifacts)
                }

                tasks.register('resolveAmbiguous', Resolve) {
                    artifacts.from(configurations.producerArtifacts.incoming.artifactView {
                        attributes {
                            attribute(usage, 'java-runtime')
                            attribute(libraryelements, 'jar')
                        }
                    }.files)
                }
            """
        }
    }

    def 'resolves ambiguous configuration'() {
        when:
        file('consumer/build.gradle') << '''
            resolve {
                expectations = [ 'producer-foo' ] // a directory
            }
        '''

        then:
        succeeds ':consumer:resolve'
//        succeeds ':consumer:resolveAmbiguous'
    }
}
