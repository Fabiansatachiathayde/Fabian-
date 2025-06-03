/*
 * Copyright 2015 the original author or authors.
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

package org.gradle.internal.operations

import org.gradle.api.GradleException
import org.gradle.internal.concurrent.DefaultParallelismConfiguration
import org.gradle.internal.resources.DefaultResourceLockCoordinationService
import org.gradle.internal.resources.ResourceLockCoordinationService
import org.gradle.internal.work.DefaultWorkerLeaseService
import org.gradle.internal.work.WorkerLeaseRegistry
import org.gradle.internal.work.WorkerLeaseService
import spock.lang.Specification

import java.util.concurrent.CountDownLatch
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class DefaultBuildOperationQueueTest extends Specification {

    public static final String LOG_LOCATION = "<log location>"
    abstract static class TestBuildOperation implements RunnableBuildOperation {
        BuildOperationDescriptor.Builder description() { BuildOperationDescriptor.displayName(toString()) }

        String toString() { getClass().simpleName }
    }

    static class Success extends TestBuildOperation {
        void run(BuildOperationContext buildOperationContext) {
            // do nothing
        }
    }

    static class Failure extends TestBuildOperation {
        void run(BuildOperationContext buildOperationContext) {
            throw new BuildOperationFailure(this, "always fails")
        }
    }

    static class SimpleWorker implements BuildOperationQueue.QueueWorker<TestBuildOperation> {
        void execute(TestBuildOperation run) {
            run.run(null)
        }

        String getDisplayName() {
            return getClass().simpleName
        }
    }

    static class BlockingWorker implements BuildOperationQueue.QueueWorker<TestBuildOperation> {
        private final CyclicBarrier barrier
        private final AtomicInteger workersStarted

        BlockingWorker(CyclicBarrier barrier, AtomicInteger workersStarted) {
            this.barrier = barrier
            this.workersStarted = workersStarted
        }

        void execute(TestBuildOperation run) {
            def currentCount = workersStarted.incrementAndGet()
            def waitCount = barrier.getParties() - currentCount
            if (waitCount >= 0) {
                println "started worker in thread ${Thread.currentThread().id} (waiting for ${barrier.getParties() - currentCount}).."
                barrier.await(5, TimeUnit.SECONDS)
            }
            run.run(null)
        }

        String getDisplayName() {
            return getClass().simpleName
        }
    }

    ResourceLockCoordinationService coordinationService
    BuildOperationQueue operationQueue
    WorkerLeaseService workerRegistry
    WorkerLeaseRegistry.WorkerLeaseCompletion lease

    void setupQueue(int threads) {
        coordinationService = new DefaultResourceLockCoordinationService()
        workerRegistry = new DefaultWorkerLeaseService(coordinationService, new DefaultParallelismConfiguration(true, threads)) {}
        lease = workerRegistry.startWorker()
        operationQueue = new DefaultBuildOperationQueue(false, workerRegistry, Executors.newFixedThreadPool(threads), new SimpleWorker())
    }

    def "cleanup"() {
        lease?.leaseFinish()
        workerRegistry.stop()
    }

    def "executes all #runs operations in #threads threads"() {
        given:
        setupQueue(threads)
        def success = Mock(TestBuildOperation)

        when:
        runs.times { operationQueue.add(success) }

        and:
        operationQueue.waitForCompletion()

        then:
        runs * success.run(_)

        where:
        runs | threads
        0    | 1
        0    | 4
        0    | 10
        1    | 1
        1    | 4
        1    | 10
        5    | 1
        5    | 4
        5    | 10
    }

    def "does not submit more workers than #threads threads"() {
        given:
        setupQueue(threads)
        def success = Mock(TestBuildOperation)
        def workerCount = Math.min(runs, threads)
        def workersStarted = new AtomicInteger()
        def barrier = new CyclicBarrier(workerCount, { println "all expected concurrent workers have started..." })
        def executorService = Mock(ExecutorService)
        def delegateExecutor = Executors.newFixedThreadPool(threads)
        operationQueue = new DefaultBuildOperationQueue(false, workerRegistry, executorService, new BlockingWorker(barrier, workersStarted))

        println "expecting ${workerCount} concurrent workers to be started..."

        when:
        runs.times { operationQueue.add(success) }

        and:
        operationQueue.waitForCompletion()

        then:
        runs * success.run(_)
        // The main thread sometimes processes items when there are more items than threads available, so
        // we may only submit workerCount - 1 worker threads, but we should never submit more than workerCount
        // threads
        (_..workerCount) * executorService.execute(_) >> { args -> delegateExecutor.execute(args[0]) }

        where:
        runs | threads
        1    | 1
        1    | 4
        1    | 10
        5    | 1
        5    | 4
        5    | 10
        20   | 10
    }

    def "cannot use operation queue once it has completed"() {
        given:
        setupQueue(1)
        operationQueue.waitForCompletion()

        when:
        operationQueue.add(Mock(TestBuildOperation))

        then:
        thrown IllegalStateException
    }

    def "failures propagate to caller regardless of when it failed #operations with #threads threads"() {
        given:
        setupQueue(threads)
        operations.each { operation ->
            operationQueue.add(operation)
        }
        def failureCount = operations.findAll({ it instanceof Failure }).size()

        when:
        operationQueue.waitForCompletion()

        then:
        // assumes we don't fail early
        MultipleBuildOperationFailures e = thrown()
        e.getCauses().every({ it instanceof GradleException })
        e.getCauses().size() == failureCount

        where:
        [operations, threads] << [
            [[new Success(), new Success(), new Failure()],
             [new Success(), new Failure(), new Success()],
             [new Failure(), new Success(), new Success()],
             [new Failure(), new Failure(), new Failure()],
             [new Failure(), new Failure(), new Success()],
             [new Failure(), new Success(), new Failure()],
             [new Success(), new Failure(), new Failure()]],
            [1, 4, 10]].combinations()
    }

    def "when log location is set value is propagated in exceptions"() {
        given:
        setupQueue(1)
        operationQueue.setLogLocation(LOG_LOCATION)
        operationQueue.add(Stub(TestBuildOperation) {
            run(_) >> { throw new RuntimeException("first") }
        })

        when:
        operationQueue.waitForCompletion()

        then:
        MultipleBuildOperationFailures e = thrown()
        e.message.contains(LOG_LOCATION)
    }

    def "when queue is canceled, unstarted operations do not execute (#runs runs, #threads threads)"() {
        def expectedInvocations = threads <= runs ? threads : runs
        CountDownLatch startedLatch = new CountDownLatch(expectedInvocations)
        CountDownLatch releaseLatch = new CountDownLatch(1)
        def operationAction = Mock(Runnable)

        given:
        setupQueue(threads)
        lease.leaseFinish() // Release worker lease to allow operation to run, when there is max 1 worker thread

        when:
        runs.times { operationQueue.add(new SynchronizedBuildOperation(operationAction, startedLatch, releaseLatch)) }
        // wait for operations to begin running
        startedLatch.await()

        and:
        operationQueue.cancel()

        and:
        // release the running operations to complete
        releaseLatch.countDown()
        workerRegistry.runAsWorkerThread {
            operationQueue.waitForCompletion()
        }

        then:
        expectedInvocations * operationAction.run()

        where:
        runs | threads
        0    | 1
        0    | 4
        0    | 10
        1    | 1
        1    | 4
        1    | 10
        5    | 1
        5    | 4
        5    | 10
    }

    static class SynchronizedBuildOperation extends TestBuildOperation {
        final Runnable operationAction
        final CountDownLatch startedLatch
        final CountDownLatch releaseLatch

        SynchronizedBuildOperation(Runnable operationAction, CountDownLatch startedLatch, CountDownLatch releaseLatch) {
            this.operationAction = operationAction
            this.startedLatch = startedLatch
            this.releaseLatch = releaseLatch
        }

        @Override
        void run(BuildOperationContext context) {
            operationAction.run()
            startedLatch.countDown()
            releaseLatch.await()
        }
    }
}
