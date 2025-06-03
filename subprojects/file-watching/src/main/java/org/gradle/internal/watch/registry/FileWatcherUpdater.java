/*
 * Copyright 2020 the original author or authors.
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

package org.gradle.internal.watch.registry;

import org.gradle.internal.snapshot.FileSystemLocationSnapshot;
import org.gradle.internal.snapshot.SnapshotHierarchy;
import org.gradle.internal.watch.vfs.WatchMode;

import javax.annotation.CheckReturnValue;
import java.io.File;
import java.util.Collection;

public interface FileWatcherUpdater {
    /**
     * Registers a watchable hierarchy.
     *
     * @see FileWatcherRegistry#registerWatchableHierarchy(File, SnapshotHierarchy)
     */
    void registerWatchableHierarchy(File watchableHierarchy, SnapshotHierarchy root);

    /**
     * Updates the watchers after changes to the root.
     *
     * @see FileWatcherRegistry#virtualFileSystemContentsChanged(Collection, Collection, SnapshotHierarchy)
     */
    void virtualFileSystemContentsChanged(Collection<FileSystemLocationSnapshot> removedSnapshots, Collection<FileSystemLocationSnapshot> addedSnapshots, SnapshotHierarchy root);

    /**
     * Trigger armed watch probe at given path.
     */
    void triggerWatchProbe(String path);

    /**
     * Remove watched hierarchies that have been moved.
     *
     * @see FileWatcherRegistry#updateVfsOnBuildStarted(SnapshotHierarchy, WatchMode)
     */
    @CheckReturnValue
    SnapshotHierarchy updateVfsOnBuildStarted(SnapshotHierarchy root, WatchMode watchMode);

    /**
     * Remove everything from the root which can't be kept after the current build finished.
     *
     * @see FileWatcherRegistry#updateVfsOnBuildFinished(SnapshotHierarchy, WatchMode, int)
     */
    @CheckReturnValue
    SnapshotHierarchy updateVfsOnBuildFinished(SnapshotHierarchy root, WatchMode watchMode, int maximumNumberOfWatchedHierarchies);

    /**
     * Returns the actual watched roots.
     *
     * These can be different from the watchable hierarchies in two ways:
     *
     * <ul>
     *     <li>hierarchies that contain no content are not watched,</li>
     *     <li>for hierarchies that do not exist on disk (but contain
     *     {@link org.gradle.internal.snapshot.MissingFileSnapshot}s),
     *     we watch the first existing parent directory.</li>
     * </ul>
     */
    Collection<File> getWatchedRoots();
}
