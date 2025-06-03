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

package org.gradle.api.internal.tasks.compile.incremental.transaction;

import org.gradle.api.internal.file.FileOperations;
import org.gradle.api.internal.tasks.compile.GroovyJavaJointCompileSpec;
import org.gradle.api.internal.tasks.compile.JavaCompileSpec;
import org.gradle.api.internal.tasks.compile.incremental.compilerapi.deps.GeneratedResource;
import org.gradle.api.tasks.util.PatternSet;
import org.gradle.internal.file.Deleter;

import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.stream.StreamSupport;

import static org.gradle.internal.FileUtils.hasExtension;

public class GroovyCompileTransaction extends AbstractCompileTransaction {

    private final JavaCompileSpec spec;

    public GroovyCompileTransaction(
        JavaCompileSpec spec,
        PatternSet classesToDelete,
        Map<GeneratedResource.Location, PatternSet> resourcesToDelete,
        FileOperations fileOperations,
        Deleter deleter
    ) {
        super(spec, classesToDelete, resourcesToDelete, fileOperations, deleter);
        this.spec = spec;
    }

    @Override
    void doStashFiles(List<StashedFile> stashedFiles) {
        if (isGroovyJavaJointCompilation()) {
            // For Groovy/Java joint compilation we have to stash files from Groovy compiler, so all previous classes can be discovered when analysing code.
            // Issue: https://github.com/gradle/gradle/issues/22531
            BeforeJavaCompilationStashRunnable stashRunnable = new BeforeJavaCompilationStashRunnable(stashedFiles);
            ((GroovyJavaJointCompileSpec) spec).setBeforeJavaCompilationRunnable(stashRunnable);
        } else {
            stashedFiles.forEach(StashedFile::stash);
        }
    }

    private boolean isGroovyJavaJointCompilation() {
        return spec instanceof GroovyJavaJointCompileSpec
            && isJavaFileCompilationEnabled((GroovyJavaJointCompileSpec) spec)
            && hasAnyJavaSourceToCompile((GroovyJavaJointCompileSpec) spec);
    }

    private boolean isJavaFileCompilationEnabled(GroovyJavaJointCompileSpec spec) {
        return spec.getGroovyCompileOptions().getFileExtensions()
            .stream().anyMatch(extension -> extension.equals("java") || extension.equals(".java"));
    }

    private boolean hasAnyJavaSourceToCompile(GroovyJavaJointCompileSpec spec) {
        return StreamSupport.stream(spec.getSourceFiles().spliterator(), false)
            .anyMatch(file -> hasExtension(file, ".java"));
    }

    private static class BeforeJavaCompilationStashRunnable implements Runnable, Serializable {
        private static final long serialVersionUID = 1L;

        private final List<StashedFile> stashedFiles;

        private BeforeJavaCompilationStashRunnable(List<StashedFile> stashedFiles) {
            this.stashedFiles = stashedFiles;
        }

        @Override
        public void run() {
            stashedFiles.forEach(StashedFile::stash);
        }
    }
}
