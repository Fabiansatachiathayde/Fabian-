/*
 * Copyright 2023 the original author or authors.
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

package org.gradle.api.internal.artifacts.configurations;

import com.google.common.collect.ImmutableSet;
import org.gradle.api.Named;
import org.gradle.api.attributes.Attribute;
import org.gradle.api.attributes.AttributeContainer;
import org.gradle.api.internal.attributes.AttributeContainerInternal;
import org.gradle.api.internal.attributes.AttributeValue;
import org.gradle.api.internal.attributes.ImmutableAttributes;
import org.gradle.api.internal.attributes.ImmutableAttributesFactory;
import org.gradle.api.provider.Provider;

import javax.annotation.Nullable;
import java.util.Arrays;
import java.util.Map;
import java.util.function.BiConsumer;

/**
 * A container of attributes that desugars the attributes on demand.
 * <p>
 * Desugaring means keeping primitive attributes (boolean and numeric) as is, and converting the rest to strings.
 * This is very similar to what other desugaring containers do (see below), but they make more assumptions about attribute types.
 *
 * @see org.gradle.api.internal.artifacts.ivyservice.resolveengine.result.DesugaredAttributeContainerSerializer
 * @see org.gradle.internal.resolve.caching.DesugaringAttributeContainerSerializer
 */
public final class LazyDesugaringAttributeContainer implements ImmutableAttributes {

    private final AttributeContainer source;
    private final ImmutableAttributesFactory attributesFactory;
    private ImmutableAttributes desugared;

    public LazyDesugaringAttributeContainer(@Nullable AttributeContainer source, ImmutableAttributesFactory attributesFactory) {
        this.source = source;
        this.attributesFactory = attributesFactory;
    }

    @Override
    public ImmutableSet<Attribute<?>> keySet() {
        return getDesugared().keySet();
    }

    @Deprecated
    @Override
    public <T> AttributeContainer attribute(Attribute<T> key, T value) {
        return getDesugared().attribute(key, value);
    }

    @Deprecated
    @Override
    public <T> AttributeContainer attributeProvider(Attribute<T> key, Provider<? extends T> provider) {
        return getDesugared().attributeProvider(key, provider);
    }

    @Nullable
    @Override
    public <T> T getAttribute(Attribute<T> key) {
        return getDesugared().getAttribute(key);
    }

    @Override
    public boolean isEmpty() {
        return getDesugared().isEmpty();
    }

    @Override
    public boolean contains(Attribute<?> key) {
        return getDesugared().contains(key);
    }

    @Override
    public AttributeContainer getAttributes() {
        return getDesugared().getAttributes();
    }

    @Override
    public ImmutableAttributes asImmutable() {
        return getDesugared();
    }

    @Override
    public Map<Attribute<?>, ?> asMap() {
        return getDesugared().asMap();
    }

    @Override
    public <T> AttributeValue<T> findEntry(Attribute<T> key) {
        return getDesugared().findEntry(key);
    }

    @Override
    public AttributeValue<?> findEntry(String key) {
        return getDesugared().findEntry(key);
    }

    @Override
    public String toString() {
        return getDesugared().toString();
    }

    @Override
    public boolean equals(Object obj) {
        return getDesugared().equals(obj);
    }

    @Override
    public int hashCode() {
        return getDesugared().hashCode();
    }

    private ImmutableAttributes getDesugared() {
        if (desugared == null) {
            desugarAttributes();
        }
        return desugared;
    }

    @SuppressWarnings("unchecked")
    private void desugarAttributes() {
        AttributeContainerInternal result = attributesFactory.mutable();
        if (source != null) {
            for (Attribute<?> attribute : source.keySet()) {
                desugar(attribute, source.getAttribute(attribute), result::attribute);
            }
        }
        desugared = result.asImmutable();
    }

    @SuppressWarnings("unchecked")
    public static void desugar(Attribute<?> attribute, Object attributeValue, BiConsumer<Attribute<Object>, Object> consumer) {
        String name = attribute.getName();
        Class<?> type = attribute.getType();

        if (type.equals(Boolean.class) || type.equals(Integer.class) || type.equals(String.class)) {
            consumer.accept((Attribute<Object>) attribute, attributeValue);
            return;
        }

        // just serialize as a String as best we can
        Attribute<?> stringAtt = Attribute.of(name, String.class);
        String stringValue;
        if (attributeValue instanceof Named) {
            stringValue = ((Named) attributeValue).getName();
        } else if (attributeValue instanceof Object[]) { // don't bother trying to handle primitive arrays specially
            stringValue = Arrays.toString((Object[]) attributeValue);
        } else {
            stringValue = attributeValue.toString();
        }
        consumer.accept((Attribute<Object>) stringAtt, stringValue);
    }
}
