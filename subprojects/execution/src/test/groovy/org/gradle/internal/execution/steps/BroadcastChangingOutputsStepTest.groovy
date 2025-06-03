/*
 * Copyright 2019 the original author or authors.
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

package org.gradle.internal.execution.steps

import org.gradle.api.file.FileCollection
import org.gradle.internal.execution.ChangingFilesRunner
import org.gradle.internal.execution.UnitOfWork
import org.gradle.internal.file.TreeType

class BroadcastChangingOutputsStepTest extends StepSpec<InputChangesContext> {
    def changingFilesRunner = Mock(ChangingFilesRunner)
    def step = new BroadcastChangingOutputsStep<>(changingFilesRunner, delegate)
    def delegateResult = Mock(Result)

    @Override
    protected InputChangesContext createContext() {
        return Stub(InputChangesContext)
    }

    def "notifies listener about specific outputs changing"() {
        def outputDir = file("output-dir")
        def localStateDir = file("local-state-dir")
        def destroyableDir = file("destroyable-dir")
        def changingOutputs = [
            outputDir.absolutePath,
            destroyableDir.absolutePath,
            localStateDir.absolutePath
        ]

        when:
        def result = step.execute(work, context)

        then:
        result == delegateResult

        _ * work.visitOutputs(_ as File, _ as UnitOfWork.OutputVisitor) >> { File workspace, UnitOfWork.OutputVisitor visitor ->
            visitor.visitOutputProperty("output", TreeType.DIRECTORY, outputDir, Mock(FileCollection))
            visitor.visitDestroyable(destroyableDir)
            visitor.visitLocalState(localStateDir)
        }

        then:
        1 * changingFilesRunner.changeFiles(changingOutputs, _) >> { outputs, changeLocationsAction ->
            changeLocationsAction.get()
        }

        then:
        1 * delegate.execute(work, _ as ChangesOutputContext) >> delegateResult

        then:
        0 * _
    }
}
