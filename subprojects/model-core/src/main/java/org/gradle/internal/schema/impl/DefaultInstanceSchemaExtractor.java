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

package org.gradle.internal.schema.impl;

import com.google.common.collect.ImmutableSortedSet;
import org.gradle.internal.properties.annotations.PropertyMetadata;
import org.gradle.internal.properties.annotations.TypeMetadata;
import org.gradle.internal.properties.annotations.TypeMetadataStore;
import org.gradle.internal.properties.annotations.TypeMetadataWalker;
import org.gradle.internal.reflect.validation.TypeValidationContext;
import org.gradle.internal.schema.InstanceSchema;
import org.gradle.internal.schema.InstanceSchemaExtractor;
import org.gradle.internal.schema.PropertySchema;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.lang.annotation.Annotation;
import java.util.function.Supplier;
import java.util.stream.Stream;

public class DefaultInstanceSchemaExtractor implements InstanceSchemaExtractor {

    private final TypeMetadataStore typeMetadataStore;
    private final TypeMetadataWalker<Object> walker;

    public DefaultInstanceSchemaExtractor(TypeMetadataStore typeMetadataStore, Class<? extends Annotation> nestedAnnotation) {
        this.typeMetadataStore = typeMetadataStore;
        this.walker = TypeMetadataWalker.instanceWalker(typeMetadataStore, nestedAnnotation);
    }

    @Override
    public InstanceSchema extractSchema(Object instance, TypeValidationContext validationContext) {
        TypeMetadata instanceMetadata = typeMetadataStore.getTypeMetadata(instance.getClass());
        PropertySchemaCollectorVisitor visitor = new PropertySchemaCollectorVisitor(validationContext);
        walker.walk(instance, visitor);
        ImmutableSortedSet<PropertySchema> properties = visitor.getProperties();
        return new DefaultInstanceSchema(instanceMetadata, properties);
    }

    private static class PropertySchemaCollectorVisitor implements TypeMetadataWalker.NodeMetadataVisitor<Object> {
        private final ImmutableSortedSet.Builder<PropertySchema> properties = ImmutableSortedSet.naturalOrder();
        private final TypeValidationContext validationContext;

        public PropertySchemaCollectorVisitor(TypeValidationContext validationContext) {
            this.validationContext = validationContext;
        }

        @Override
        public void visitRoot(TypeMetadata typeMetadata, Object value) {
            typeMetadata.visitValidationFailures(null, validationContext);
        }

        @Override
        public void visitNested(TypeMetadata typeMetadata, String qualifiedName, PropertyMetadata propertyMetadata, Object value) {
            typeMetadata.visitValidationFailures(qualifiedName, validationContext);
            properties.add(new NestedPropertySchema(qualifiedName, propertyMetadata, value));
        }

        @Override
        public void visitLeaf(String qualifiedName, PropertyMetadata propertyMetadata, Supplier<Object> value) {
            properties.add(new LeafPropertySchema(qualifiedName, propertyMetadata, value));
        }

        public ImmutableSortedSet<PropertySchema> getProperties() {
            return properties.build();
        }
    }

    private static class DefaultInstanceSchema implements InstanceSchema {
        private final TypeMetadata typeMetadata;
        private final ImmutableSortedSet<PropertySchema> properties;

        public DefaultInstanceSchema(TypeMetadata typeMetadata, ImmutableSortedSet<PropertySchema> properties) {
            this.typeMetadata = typeMetadata;
            this.properties = properties;
        }

        @Override
        public TypeMetadata getTypeMetadata() {
            return typeMetadata;
        }

        @Override
        public Stream<PropertySchema> properties() {
            return properties.stream();
        }
    }

    private abstract static class AbstractPropertySchema implements PropertySchema {
        private final String qualifiedName;
        private final PropertyMetadata metadata;

        public AbstractPropertySchema(String qualifiedName, PropertyMetadata metadata) {
            this.qualifiedName = qualifiedName;
            this.metadata = metadata;
        }

        @Override
        public String getQualifiedName() {
            return qualifiedName;
        }

        @Override
        public PropertyMetadata getMetadata() {
            return metadata;
        }

        @Override
        public int compareTo(@Nonnull PropertySchema o) {
            return qualifiedName.compareTo(o.getQualifiedName());
        }
    }

    private static class NestedPropertySchema extends AbstractPropertySchema {
        private final Object value;

        public NestedPropertySchema(String qualifiedName, PropertyMetadata metadata, Object value) {
            super(qualifiedName, metadata);
            this.value = value;
        }

        @Nullable
        @Override
        public Object getValue() {
            return value;
        }
    }

    private static class LeafPropertySchema extends AbstractPropertySchema {
        private final Supplier<Object> value;

        public LeafPropertySchema(String qualifiedName, PropertyMetadata metadata, Supplier<Object> value) {
            super(qualifiedName, metadata);
            this.value = value;
        }

        @Nullable
        @Override
        public Object getValue() {
            return value.get();
        }
    }
}
