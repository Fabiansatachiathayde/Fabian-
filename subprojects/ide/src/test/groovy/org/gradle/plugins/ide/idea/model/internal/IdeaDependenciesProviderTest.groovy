/*
 * Copyright 2014 the original author or authors.
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

package org.gradle.plugins.ide.idea.model.internal

import org.gradle.api.artifacts.Configuration
import org.gradle.api.internal.project.ProjectInternal
import org.gradle.plugins.ide.idea.IdeaPlugin
import org.gradle.plugins.ide.idea.model.Dependency
import org.gradle.plugins.ide.idea.model.ModuleLibrary
import org.gradle.plugins.ide.idea.model.Path
import org.gradle.plugins.ide.idea.model.SingleEntryModuleLibrary
import org.gradle.plugins.ide.internal.IdeArtifactRegistry
import org.gradle.plugins.ide.internal.resolver.NullGradleApiSourcesResolver
import org.gradle.test.fixtures.AbstractProjectBuilderSpec
import org.gradle.test.fixtures.ModuleArtifact
import org.gradle.test.fixtures.maven.MavenFileRepository
import org.gradle.test.fixtures.maven.MavenModule
import org.gradle.test.fixtures.server.http.BlockingHttpServer
import org.gradle.util.TestUtil
import org.junit.Rule

import java.util.stream.Collectors

class IdeaDependenciesProviderTest extends AbstractProjectBuilderSpec {
    @Rule
    public BlockingHttpServer blockingServer = new BlockingHttpServer()

    public final MavenFileRepository mavenRepo = new MavenFileRepository(temporaryFolder.testDirectory.file("maven-repo"))
    private ProjectInternal childProject
    private IdeArtifactRegistry artifactRegistry
    private IdeaDependenciesProvider dependenciesProvider

    def setup() {
        childProject = TestUtil.createChildProject(project, "child", temporaryFolder.testDirectory.file("child"))
        artifactRegistry = Stub(IdeArtifactRegistry)
        dependenciesProvider = new IdeaDependenciesProvider(project, artifactRegistry, NullGradleApiSourcesResolver.INSTANCE)

        _ * artifactRegistry.getIdeProject(_, _) >> { Class c, def m ->
            return Stub(c)
        }

        blockingServer.start()
    }

    def "no dependencies test"() {
        applyPluginToProjects()
        project.apply(plugin: 'java')

        def module = project.ideaModule.module // Mock(IdeaModule)
        module.offline = true

        when:
        def result = dependenciesProvider.provide(module)

        then:
        result.isEmpty()
    }

    def "dependencies are added to each required scope"() {
        applyPluginToProjects()
        project.apply(plugin: 'java')

        def module = project.ideaModule.module // Mock(IdeaModule)
        module.offline = true

        when:
        project.dependencies.add('implementation', project.layout.files('lib/guava.jar'))
        project.dependencies.add('testImplementation', project.layout.files('lib/mockito.jar'))
        def result = dependenciesProvider.provide(module)

        then:
        result.size() == 2
        assertSingleLibrary(result, 'COMPILE', 'guava.jar')
        assertSingleLibrary(result, 'TEST', 'mockito.jar')
    }

    def "dependency is excluded if added to minus configuration"() {
        applyPluginToProjects()
        project.apply(plugin: 'java')

        def module = project.ideaModule.module // Mock(IdeaModule)
        project.configurations.create('excluded')
        module.offline = false

        when:
        project.dependencies.add('testRuntimeOnly', project.layout.files('lib/guava.jar'))
        project.dependencies.add('excluded', project.layout.files('lib/guava.jar'))
        module.scopes.TEST.minus << project.configurations.getByName('excluded')
        def result = dependenciesProvider.provide(module)

        then:
        result.size() == 0
    }

    def "dependency is excluded if added to any minus configuration"() {
        applyPluginToProjects()
        project.apply(plugin: 'java')

        def module = project.ideaModule.module // Mock(IdeaModule)
        project.configurations.create('excluded1')
        project.configurations.create('excluded2')
        module.offline = true

        when:
        project.dependencies.add('testRuntimeOnly', project.layout.files('lib/guava.jar'))
        project.dependencies.add('testRuntimeOnly', project.layout.files('lib/slf4j-api.jar'))
        project.dependencies.add('excluded1', project.layout.files('lib/guava.jar'))
        project.dependencies.add('excluded2', project.layout.files('lib/slf4j-api.jar'))
        module.scopes.TEST.minus << project.configurations.getByName('excluded1')
        module.scopes.TEST.minus << project.configurations.getByName('excluded2')
        def result = dependenciesProvider.provide(module)

        then:
        result.size() == 0
    }

    def "dependency is added from plus detached configuration"() {
        applyPluginToProjects()
        project.apply(plugin: 'java')

        def module = project.ideaModule.module
        def extraDependency = project.dependencies.create(project.layout.files('lib/guava.jar'))
        def detachedCfg = project.configurations.detachedConfiguration(extraDependency)
        module.offline = false

        when:
        module.scopes.RUNTIME.plus << detachedCfg
        def result = dependenciesProvider.provide(module)

        then:
        result.size() == 1
        result.findAll { Dependency it -> it.scope == 'RUNTIME' }.size() == 1
    }

    def "compile dependency on child project"() {
        applyPluginToProjects()
        project.apply(plugin: 'java')
        childProject.apply(plugin: 'java')

        def module = project.ideaModule.module // Mock(IdeaModule)
        module.offline = true

        when:
        project.dependencies.add('implementation', childProject)
        def result = dependenciesProvider.provide(module)

        then:
        result.size() == 1
        result.findAll { it.scope == 'COMPILE' }.size() == 1
    }

    def "testCompile dependency on current project (self-dependency)"() {
        applyPluginToProjects()
        project.apply(plugin: 'java')
        childProject.apply(plugin: 'java')

        def module = project.ideaModule.module // Mock(IdeaModule)
        module.offline = true

        when:
        project.dependencies.add('testImplementation', project)
        def result = dependenciesProvider.provide(module)

        then:
        result.size() == 0
    }

    def "test and runtime scope for the same dependency"() {
        applyPluginToProjects()
        project.apply(plugin: 'java')

        def module = project.ideaModule.module // Mock(IdeaModule)
        module.offline = true

        when:
        project.dependencies.add('testImplementation', project.layout.files('lib/foo-impl.jar'))
        project.dependencies.add('runtimeOnly', project.layout.files('lib/foo-impl.jar'))
        def result = dependenciesProvider.provide(module)

        then:
        result.size() == 2
        assertSingleLibrary(result, 'TEST', 'foo-impl.jar')
        assertSingleLibrary(result, 'RUNTIME', 'foo-impl.jar')
    }

    def "compile only dependencies"() {
        applyPluginToProjects()
        project.apply(plugin: 'java')

        def module = project.ideaModule.module // Mock(IdeaModule)
        module.offline = true

        when:
        project.dependencies.add('compileOnly', project.layout.files('lib/foo-api.jar'))
        project.dependencies.add('testRuntimeOnly', project.layout.files('lib/foo-impl.jar'))
        def result = dependenciesProvider.provide(module)

        then:
        result.size() == 2
        assertSingleLibrary(result, 'PROVIDED', 'foo-api.jar')
        assertSingleLibrary(result, 'TEST', 'foo-impl.jar')
    }

    def "compile only dependency conflicts with runtime dependencies"() {
        applyPluginToProjects()
        project.apply(plugin: 'java')

        def module = project.ideaModule.module // Mock(IdeaModule)
        module.offline = true

        when:
        project.dependencies.add('compileOnly', project.layout.files('lib/foo-runtime.jar'))
        project.dependencies.add('compileOnly', project.layout.files('lib/foo-testRuntime.jar'))
        project.dependencies.add('runtimeOnly', project.layout.files('lib/foo-runtime.jar'))
        project.dependencies.add('testRuntimeOnly', project.layout.files('lib/foo-testRuntime.jar'))
        def result = dependenciesProvider.provide(module)

        then:
        result.size() == 2
        assertSingleLibrary(result, 'COMPILE', 'foo-runtime.jar')
        assertSingleLibrary(result, 'PROVIDED', 'foo-testRuntime.jar')
    }

    def "ignore unknown configurations"() {
        applyPluginToProjects()
        project.apply(plugin: 'java')

        def module = project.ideaModule.module // Mock(IdeaModule)
        module.offline = true
        def extraConfiguration = project.configurations.create('extraConfiguration')

        when:
        project.dependencies.add('testImplementation', project.layout.files('lib/mockito.jar'))
        def result = dependenciesProvider.provide(module)

        then:
        extraConfiguration.state == Configuration.State.UNRESOLVED
        result.size() == 1
        result.findAll { it.scope == 'TEST' }.size() == 1
    }

    def "serial IDS - the old way - fails"() {
        project.gradle.startParameter.dependencyVerificationMode = org.gradle.api.artifacts.verification.DependencyVerificationMode.OFF
        project.configurations.configureEach() { conf ->
            conf.getResolutionStrategy().disableDependencyVerification()
        }

        def m1 = mavenRepo.module('test', 'test1', '1.0')
            .withJavadoc()
            .withSources()
            .publish()
        def m2 = mavenRepo.module('test', 'test2', '1.0')
            .withJavadoc()
            .withSources()
            .publish()
        def m3 = mavenRepo.module('test', 'test3', '1.0')
            .withJavadoc()
            .withSources()
            .publish()

        def m1javadoc = getJavadocArtifact(m1)
        def m1sources = getSourcesArtifact(m1)
        def m2javadoc = getJavadocArtifact(m2)
        def m2sources = getSourcesArtifact(m2)
        def m3javadoc = getJavadocArtifact(m3)
        def m3sources = getSourcesArtifact(m3)

        applyPluginToProjects()
        project.apply(plugin: 'java')

        project.repositories {
            maven {
                url = blockingServer.uri
            }
        }

        def module = project.ideaModule.module
        module.offline = false
        module.downloadSources = true
        module.downloadJavadoc = true

        blockingServer.expectConcurrent(
            blockingServer.get(m1.pom.path).sendFile(m1.pom.file),
            blockingServer.get(m2.pom.path).sendFile(m2.pom.file),
            blockingServer.get(m3.pom.path).sendFile(m3.pom.file))

        blockingServer.expectConcurrent(
            blockingServer.get(m1.artifact.path).sendFile(m1.artifact.file),
            blockingServer.get(m2.artifact.path).sendFile(m2.artifact.file),
            blockingServer.get(m3.artifact.path).sendFile(m3.artifact.file))

        blockingServer.expectConcurrent(
            blockingServer.get(m1sources.path).sendFile(m1sources.file),
            blockingServer.get(m2sources.path).sendFile(m2sources.file),
            blockingServer.get(m3sources.path).sendFile(m3sources.file))

        blockingServer.expectConcurrent(
            blockingServer.get(m1javadoc.path).sendFile(m1javadoc.file),
            blockingServer.get(m2javadoc.path).sendFile(m2javadoc.file),
            blockingServer.get(m3javadoc.path).sendFile(m3javadoc.file))

        when:
        project.dependencies.add('testRuntimeOnly', "test:test1:1.0")
        project.dependencies.add('testRuntimeOnly', "test:test2:1.0")
        project.dependencies.add('testRuntimeOnly', "test:test3:1.0")

        def testRuntime = project.configurations.getByName("testRuntimeClasspath")

        def result = dependenciesProvider.provide(module)

        then:
        result.size() == 3
    }

    def "parallel IDS - the new way - succeeds"() {
        project.gradle.startParameter.dependencyVerificationMode = org.gradle.api.artifacts.verification.DependencyVerificationMode.OFF
        project.configurations.configureEach() { conf ->
            conf.getResolutionStrategy().disableDependencyVerification()
        }

        def m1 = mavenRepo.module('test', 'test1', '1.0')
            .withJavadoc()
            .withSources()
            .publish()
        def m2 = mavenRepo.module('test', 'test2', '1.0')
            .withJavadoc()
            .withSources()
            .publish()
        def m3 = mavenRepo.module('test', 'test3', '1.0')
            .withJavadoc()
            .withSources()
            .publish()

        def m1javadoc = getJavadocArtifact(m1)
        def m1sources = getSourcesArtifact(m1)
        def m2javadoc = getJavadocArtifact(m2)
        def m2sources = getSourcesArtifact(m2)
        def m3javadoc = getJavadocArtifact(m3)
        def m3sources = getSourcesArtifact(m3)

        applyPluginToProjects()
        project.apply(plugin: 'java')

        project.repositories {
            maven {
                url = blockingServer.uri
            }
        }

        def module = project.ideaModule.module
        module.offline = false
        module.downloadSources = true
        module.downloadJavadoc = true

        blockingServer.expectConcurrent(
            blockingServer.get(m1.pom.path).sendFile(m1.pom.file),
            blockingServer.get(m2.pom.path).sendFile(m2.pom.file),
            blockingServer.get(m3.pom.path).sendFile(m3.pom.file))

        blockingServer.expectConcurrent(
            blockingServer.get(m1.artifact.path).sendFile(m1.artifact.file),
            blockingServer.get(m2.artifact.path).sendFile(m2.artifact.file),
            blockingServer.get(m3.artifact.path).sendFile(m3.artifact.file))

        blockingServer.expectConcurrent(
            blockingServer.get(m1sources.path).sendFile(m1sources.file),
            blockingServer.get(m2sources.path).sendFile(m2sources.file),
            blockingServer.get(m3sources.path).sendFile(m3sources.file))

        blockingServer.expectConcurrent(
            blockingServer.get(m1javadoc.path).sendFile(m1javadoc.file),
            blockingServer.get(m2javadoc.path).sendFile(m2javadoc.file),
            blockingServer.get(m3javadoc.path).sendFile(m3javadoc.file))

        when:
        project.dependencies.add('testRuntimeOnly', "test:test1:1.0")
        project.dependencies.add('testRuntimeOnly', "test:test2:1.0")
        project.dependencies.add('testRuntimeOnly', "test:test3:1.0")

        def result = dependenciesProvider.provide(module, true)

        then:
        result.size() == 3
        Set<Set<Path>> sources = result.stream().map(it -> (ModuleLibrary)it).map(it -> it.getSources()).collect(Collectors.toSet())
        sources.size() == 3
        Set<Set<Path>> javadocs = result.stream().map(it -> (ModuleLibrary)it).map(it -> it.getJavadoc()).collect(Collectors.toSet())
        javadocs.size() == 3
    }

    private applyPluginToProjects() {
        project.apply plugin: IdeaPlugin
        childProject.apply plugin: IdeaPlugin
    }

    private void assertSingleLibrary(Set<Dependency> dependencies, String scope, String artifactName) {
        def size = dependencies.findAll { SingleEntryModuleLibrary module ->
            module.scope == scope && module.libraryFile.path.endsWith(artifactName)
        }.size()
        assert size == 1: "Expected single entry for artifact $artifactName in scope $scope but found $size"
    }

    private ModuleArtifact getJarArtifact(MavenModule module) {
        return getArtifactByClassifier(module, 'jar')
    }

    private ModuleArtifact getJavadocArtifact(MavenModule module) {
        return getArtifactByClassifier(module, 'javadoc')
    }

    private ModuleArtifact getSourcesArtifact(MavenModule module) {
        return getArtifactByClassifier(module, 'sources')
    }

    private ModuleArtifact getArtifactByClassifier(MavenModule module, String classifier) {
        return module.getArtifact(type: 'jar', classifier: classifier)
    }

}
