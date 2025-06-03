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

package org.gradle.internal.execution.model.impl;

import org.gradle.api.file.FileCollection;
import org.gradle.api.tasks.Classpath;
import org.gradle.api.tasks.CompileClasspath;
import org.gradle.api.tasks.IgnoreEmptyDirectories;
import org.gradle.api.tasks.PathSensitive;
import org.gradle.api.tasks.PathSensitivity;
import org.gradle.api.tasks.SkipWhenEmpty;
import org.gradle.internal.execution.model.FileCollectionResolver;
import org.gradle.internal.execution.model.InputFilePropertyModel;
import org.gradle.internal.execution.model.InputNormalizer;
import org.gradle.internal.fingerprint.DirectorySensitivity;
import org.gradle.internal.fingerprint.FileNormalizer;
import org.gradle.internal.fingerprint.LineEndingSensitivity;
import org.gradle.internal.model.PropertyModelBuilder;
import org.gradle.internal.properties.InputBehavior;
import org.gradle.internal.properties.annotations.PropertyMetadata;
import org.gradle.internal.schema.PropertySchema;
import org.gradle.work.Incremental;
import org.gradle.work.NormalizeLineEndings;

import javax.annotation.Nullable;
import java.lang.annotation.Annotation;

import static org.gradle.internal.execution.model.annotations.ModifierAnnotationCategory.NORMALIZATION;

public abstract class AbstractInputFilePropertyModelBuilder<A extends Annotation> implements PropertyModelBuilder<A, InputFilePropertyModel> {
    private final Class<A> propertyType;
    private final FileCollectionResolver fileCollectionResolver;

    public AbstractInputFilePropertyModelBuilder(Class<A> propertyType, FileCollectionResolver fileCollectionResolver) {
        this.propertyType = propertyType;
        this.fileCollectionResolver = fileCollectionResolver;
    }

    @Override
    public Class<A> getHandledPropertyType() {
        return propertyType;
    }

    @Override
    public InputFilePropertyModel getModel(PropertySchema schema) {
        Object value = schema.getValue();
        PropertyMetadata metadata = schema.getMetadata();
        FileCollection fileValue = (value == null || value instanceof FileCollection)
            ? (FileCollection) value
            : fileCollectionResolver.resolveFileCollection(value);
        return new DefaultInputFilePropertyModel(
            schema.getQualifiedName(),
            determineNormalizer(metadata),
            determineBehavior(metadata),
            determineDirectorySensitivity(metadata),
            determineLineEndingSensitivity(metadata),
            fileValue
        );
    }

    // TODO Emit a warning here and fall back to ABSOLUTE here instead of using null
    @Nullable
    private static FileNormalizer determineNormalizer(PropertyMetadata propertyMetadata) {
        return propertyMetadata.getAnnotationForCategory(NORMALIZATION)
            .map(fileNormalization -> {
                if (fileNormalization instanceof PathSensitive) {
                    PathSensitivity pathSensitivity = ((PathSensitive) fileNormalization).value();
                    return InputNormalizer.determineNormalizerForPathSensitivity(pathSensitivity);
                } else if (fileNormalization instanceof Classpath) {
                    return InputNormalizer.RUNTIME_CLASSPATH;
                } else if (fileNormalization instanceof CompileClasspath) {
                    return InputNormalizer.COMPILE_CLASSPATH;
                } else {
                    throw new IllegalStateException("Unknown normalization annotation used: " + fileNormalization);
                }
            })
            .orElse(null);
    }

    private static InputBehavior determineBehavior(PropertyMetadata propertyMetadata) {
        return propertyMetadata.isAnnotationPresent(SkipWhenEmpty.class)
            ? InputBehavior.PRIMARY
            : propertyMetadata.isAnnotationPresent(Incremental.class)
            ? InputBehavior.INCREMENTAL
            : InputBehavior.NON_INCREMENTAL;
    }

    private static LineEndingSensitivity determineLineEndingSensitivity(PropertyMetadata propertyMetadata) {
        return propertyMetadata.isAnnotationPresent(NormalizeLineEndings.class)
            ? LineEndingSensitivity.NORMALIZE_LINE_ENDINGS
            : LineEndingSensitivity.DEFAULT;
    }

    protected DirectorySensitivity determineDirectorySensitivity(PropertyMetadata propertyMetadata) {
        return propertyMetadata.isAnnotationPresent(IgnoreEmptyDirectories.class)
            ? DirectorySensitivity.IGNORE_DIRECTORIES
            : DirectorySensitivity.DEFAULT;
    }
}
