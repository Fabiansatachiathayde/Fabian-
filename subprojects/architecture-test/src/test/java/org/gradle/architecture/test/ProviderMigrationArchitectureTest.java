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

package org.gradle.architecture.test;

import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaMethod;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;
import org.gradle.StartParameter;
import org.gradle.api.DefaultTask;
import org.gradle.api.Task;
import org.gradle.api.artifacts.Configuration;
import org.gradle.api.file.ConfigurableFileCollection;
import org.gradle.api.file.FileCollection;
import org.gradle.api.internal.AbstractTask;
import org.gradle.api.provider.Provider;
import org.gradle.api.resources.TextResource;
import org.gradle.internal.reflect.PropertyAccessorType;

import javax.inject.Inject;

import static com.tngtech.archunit.base.DescribedPredicate.not;
import static com.tngtech.archunit.core.domain.JavaClass.Predicates.assignableTo;
import static com.tngtech.archunit.core.domain.JavaClass.Predicates.simpleNameEndingWith;
import static com.tngtech.archunit.core.domain.JavaMember.Predicates.declaredIn;
import static com.tngtech.archunit.lang.conditions.ArchPredicates.are;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.methods;
import static org.gradle.architecture.test.ArchUnitFixture.freeze;
import static org.gradle.architecture.test.ArchUnitFixture.public_api_methods;

@SuppressWarnings("deprecation")
@AnalyzeClasses(packages = "org.gradle")
public class ProviderMigrationArchitectureTest {
    private static final DescribedPredicate<JavaMethod> getters = new DescribedPredicate<JavaMethod>("getters") {
        @Override
        public boolean apply(JavaMethod input) {
            PropertyAccessorType accessorType = PropertyAccessorType.fromName(input.getName());
            return accessorType == PropertyAccessorType.GET_GETTER || accessorType == PropertyAccessorType.IS_GETTER;
        }
    };

    private static final DescribedPredicate<JavaMethod> haveSetters = new DescribedPredicate<JavaMethod>("have mutable property") {
        @Override
        public boolean apply(JavaMethod input) {
            PropertyAccessorType accessorType = PropertyAccessorType.fromName(input.getName());
            String propertyNameFromGetter = accessorType.propertyNameFor(input.getName());
            return input.getOwner().getAllMethods().stream()
                .filter(method -> PropertyAccessorType.fromName(method.getName()) == PropertyAccessorType.SETTER)
                .anyMatch(method -> PropertyAccessorType.SETTER.propertyNameFor(method.getName()).equals(propertyNameFromGetter));
        }
    };

    private static final DescribedPredicate<JavaClass> haveMutableProperty = new DescribedPredicate<JavaClass>("getters") {
        @Override
        public boolean apply(JavaClass input) {
            return input.getAllMethods().stream()
                .filter(getters::apply)
                .anyMatch(haveSetters::apply);
        }
    };

    @ArchTest
    public static final ArchRule mutable_public_api_properties_should_be_providers = freeze(methods()
        .that(are(public_api_methods))
        .and(not(declaredIn(assignableTo(Task.class))))
        .and(are(declaredIn(haveMutableProperty)))
        .and(are(getters))
        .and().areNotAnnotatedWith(Inject.class)
        .and().areNotDeclaredIn(StartParameter.class)
        .and().areNotDeclaredIn(Configuration.class)
        .and().areNotDeclaredIn(ConfigurableFileCollection.class)
        .and().areNotDeclaredIn(FileCollection.class)
        .and().doNotHaveRawReturnType(TextResource.class)
        .and().doNotHaveRawReturnType(assignableTo(FileCollection.class))
        .should().haveRawReturnType(assignableTo(Provider.class)));

    @ArchTest
    public static final ArchRule mutable_public_api_properties_should_be_file_collections = freeze(methods()
        .that(are(public_api_methods))
        .and(not(declaredIn(assignableTo(Task.class))))
        .and(are(getters))
        .and(haveSetters)
        .and().areNotAnnotatedWith(Inject.class)
        .and().haveRawReturnType(assignableTo(FileCollection.class))
        .should().haveRawReturnType(assignableTo(ConfigurableFileCollection.class)));

    @SuppressWarnings("deprecation")
    @ArchTest
    public static final ArchRule public_api_task_properties_are_providers = freeze(methods()
        .that(are(public_api_methods))
        .and(are(declaredIn(assignableTo(Task.class))))
        .and(are(getters))
        .and().areNotDeclaredIn(Task.class)
        .and().areNotDeclaredIn(DefaultTask.class)
        .and().areNotDeclaredIn(AbstractTask.class)
        .and().areNotAnnotatedWith(Inject.class)
        .and().doNotHaveRawReturnType(TextResource.class)
        .and().doNotHaveRawReturnType(assignableTo(FileCollection.class))
        .should().haveRawReturnType(assignableTo(Provider.class)));

    @SuppressWarnings("deprecation")
    @ArchTest
    public static final ArchRule public_api_task_file_properties_are_configurable_file_collections = freeze(methods()
        .that(are(public_api_methods))
        .and(are(declaredIn(assignableTo(Task.class))))
        .and(are(getters))
        .and().areNotDeclaredIn(Task.class)
        .and().areNotDeclaredIn(DefaultTask.class)
        .and().areNotDeclaredIn(AbstractTask.class)
        .and().areNotAnnotatedWith(Inject.class)
        .and().haveRawReturnType(assignableTo(FileCollection.class))
        .should().haveRawReturnType(assignableTo(ConfigurableFileCollection.class)));

    @SuppressWarnings("deprecation")
    @ArchTest
    public static final ArchRule public_api_task_properties_should_not_use_text_resources = freeze(methods()
        .that(are(public_api_methods))
        .and(are(declaredIn(assignableTo(Task.class))))
        .and(are(getters))
        .and().areNotDeclaredIn(Task.class)
        .and().areNotDeclaredIn(DefaultTask.class)
        .and().areNotDeclaredIn(AbstractTask.class)
        .and().areNotAnnotatedWith(Inject.class)
        .should().notHaveRawReturnType(TextResource.class));

    @ArchTest
    public static final ArchRule public_api_extension_properties_are_providers = freeze(methods()
        .that(are(public_api_methods))
        .and(are(not(declaredIn(assignableTo(Task.class)))))
        .and(are(declaredIn(simpleNameEndingWith("Extension"))))
        .and(are(getters))
        .and().areNotAnnotatedWith(Inject.class)
        .should().haveRawReturnType(assignableTo(Provider.class)));
}
