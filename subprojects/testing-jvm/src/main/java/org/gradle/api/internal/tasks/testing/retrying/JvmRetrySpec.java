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

package org.gradle.api.internal.tasks.testing.retrying;

import javax.annotation.Nullable;
import java.io.Serializable;

public class JvmRetrySpec implements Serializable {

    private final long maxRetries;
    private final boolean stopRetryingAfterFailure;

    private JvmRetrySpec(long maxRetries, boolean stopRetryingAfterFailure) {
        this.maxRetries = maxRetries;
        this.stopRetryingAfterFailure = stopRetryingAfterFailure;
    }

    public long getMaxRetries() {
        return maxRetries;
    }

    public boolean isStopRetryingAfterFailure() {
        return stopRetryingAfterFailure;
    }

    /**
     * Due to Java6 compatibility we can't accept Provider here, so we use Long.
     */
    public static JvmRetrySpec of(@Nullable Long retryUntilFailureCount, @Nullable Long retryUntilStoppedCount) {
        if (retryUntilFailureCount != null) {
            return new JvmRetrySpec(retryUntilFailureCount, true);
        } else if (retryUntilStoppedCount != null) {
            return new JvmRetrySpec(retryUntilStoppedCount, false);
        }
        return noRetries();
    }

    public static JvmRetrySpec noRetries() {
        return new JvmRetrySpec(1, false);
    }
}
