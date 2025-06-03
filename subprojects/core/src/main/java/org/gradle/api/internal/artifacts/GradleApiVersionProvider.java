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

package org.gradle.api.internal.artifacts;

import org.gradle.api.UncheckedIOException;
import org.gradle.api.artifacts.Configuration;
import org.gradle.api.artifacts.Dependency;
import org.gradle.api.artifacts.SelfResolvingDependency;
import org.gradle.api.artifacts.dsl.DependencyHandler;
import org.gradle.api.artifacts.dsl.RepositoryHandler;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Optional;
import java.util.Set;

public class GradleApiVersionProvider {

    public static final String GRADLE_API_SOURCE_VERSION_PROPERTY = "org.gradle.api.source-version";
    public static final String GRADLE_VERSION_MARKER = "META-INF/org.gradle/gradle-version.properties";
    private static final String GRADLE_API_REPO_NAME = "gradle-internal-added-gradle-api-repo";

    public static Optional<String> getGradleApiSourceVersion() {
        return Optional.ofNullable(System.getProperty(GRADLE_API_SOURCE_VERSION_PROPERTY));
    }

    public static void addGradleSourceApiRepository(RepositoryHandler repositoryHandler) {
        getGradleApiSourceVersion().ifPresent(version -> {
            if (repositoryHandler.findByName(GRADLE_API_REPO_NAME) == null) {
                String repositoryUrl = System.getProperty("gradle.api.repository.url", "https://repo.gradle.org/gradle/libs-releases");
                repositoryHandler.maven(repo -> {
                    repo.setUrl(repositoryUrl);
                    repo.setName(GRADLE_API_REPO_NAME);
                });
            }
        });
    }

    public static void addToConfiguration(Configuration configuration, DependencyHandler repositoryHandler) {
        Dependency gradleApiDependency = getGradleApiSourceVersion()
            .map(repositoryHandler::gradleApi)
            .orElseGet(repositoryHandler::gradleApi);
        configuration.getDependencies().add(gradleApiDependency);
        if (getGradleApiSourceVersion().isPresent()) {
            configuration.getDependencies().add(repositoryHandler.create("org.codehaus.groovy:groovy:3.0.10"));
            configuration.getDependencies().add(repositoryHandler.create("javax.inject:javax.inject:1"));
            configuration.getDependencies().add(repositoryHandler.create("org.slf4j:slf4j-api:1.7.30"));
            configuration.getDependencies().add(repositoryHandler.create("org.apache.ant:ant:1.10.11"));
        }
    }

    public static Collection<File> resolveGradleSourceApi(DependencyResolutionServices dependencyResolutionServices) {
        return getGradleApiSourceVersion()
            .map(version -> gradleApisFromRepository(dependencyResolutionServices, version))
            .orElseGet(() -> gradleApisFromCurrentGradle(dependencyResolutionServices.getDependencyHandler()));
    }

    public static void createGradleVersionMarker(File classesDirectory) {
        if (!GradleApiVersionProvider.getGradleApiSourceVersion().isPresent()) {
            Path versionMarker = classesDirectory.toPath().resolve(GradleApiVersionProvider.GRADLE_VERSION_MARKER);
            if (!Files.exists(versionMarker)) {
                try {
                    Files.createDirectories(versionMarker.getParent());
                    Files.createFile(versionMarker);
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            }
        }
    }

    private static Set<File> gradleApisFromCurrentGradle(DependencyHandler dependencyHandler) {
        SelfResolvingDependency gradleApiDependency = (SelfResolvingDependency) dependencyHandler.gradleApi();
        return gradleApiDependency.resolve();

    }
    private static Set<File> gradleApisFromRepository(DependencyResolutionServices dependencyResolutionServices, String version) {
        addGradleSourceApiRepository(dependencyResolutionServices.getResolveRepositoryHandler());
        Configuration detachedConfiguration = dependencyResolutionServices.getConfigurationContainer().detachedConfiguration(dependencyResolutionServices.getDependencyHandler().gradleApi(version));
        return detachedConfiguration.resolve();
    }
}
