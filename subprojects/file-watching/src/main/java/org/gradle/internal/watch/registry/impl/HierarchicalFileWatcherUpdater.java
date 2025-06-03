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

package org.gradle.internal.watch.registry.impl;

import net.rubygrapefruit.platform.file.FileWatcher;
import org.gradle.internal.snapshot.FileSystemLocationSnapshot;
import org.gradle.internal.snapshot.SnapshotHierarchy;
import org.gradle.internal.watch.registry.FileWatcherProbeRegistry;
import org.gradle.internal.watch.registry.FileWatcherUpdater;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.Collection;

/**
 * Updater for hierarchical file watchers.
 *
 * For hierarchical watchers, we can use the registered watchable hierarchies as watched directories.
 * Build root directories are always watchable hierarchies.
 * Watching the build root directories is better since they are less likely to be deleted and
 * nearly no changes to the watched directories are necessary when running builds on the same project.
 *
 * To allow deleting the build root directories, we need to stop watching a build root directory if there are no more snapshots in the VFS inside,
 * since watched directories can't be deleted on Windows.
 *
 * The build root directories are discovered as included builds are encountered at the start of a build, and then they are removed when the build finishes.
 *
 * This is the lifecycle for the watchable hierarchies:
 * - During a build, there will be various calls to {@link FileWatcherUpdater#registerWatchableHierarchy(File, SnapshotHierarchy)},
 *   each call augmenting the collection. The watchers will be updated accordingly.
 * - When updating the watches, we watch watchable hierarchies registered for this build or old watched directories from previous builds instead of
 *   directories inside them.
 * - At the end of the build
 *   - stop watching the watchable directories with nothing to watch inside
 *   - remember the currently watched directories as old watched directories for the next build
 *   - remove everything that isn't watched from the virtual file system.
 */
public class HierarchicalFileWatcherUpdater extends AbstractFileWatcherUpdater {
    private static final Logger LOGGER = LoggerFactory.getLogger(HierarchicalFileWatcherUpdater.class);

    private final FileWatcher fileWatcher;
    private final MovedHierarchyHandler movedHierarchyHandler;

    public HierarchicalFileWatcherUpdater(
        FileWatcher fileWatcher,
        FileSystemLocationToWatchValidator locationToWatchValidator,
        FileWatcherProbeRegistry probeRegistry, WatchableHierarchies watchableHierarchies,
        MovedHierarchyHandler movedHierarchyHandler
    ) {
        super(locationToWatchValidator, probeRegistry, watchableHierarchies);
        this.fileWatcher = fileWatcher;
        this.movedHierarchyHandler = movedHierarchyHandler;
    }

    @Override
    protected boolean handleVirtualFileSystemContentsChanged(Collection<FileSystemLocationSnapshot> removedSnapshots, Collection<FileSystemLocationSnapshot> addedSnapshots, SnapshotHierarchy root) {
        return watchableHierarchies.getRecentlyUsedHierarchies().stream().anyMatch(watchableHierarchy -> {
            boolean hasSnapshotsToWatch = root.hasDescendantsUnder(watchableHierarchy.getPath());
            if (watchedHierarchies.contains(watchableHierarchy)) {
                // Need to stop watching this hierarchy
                return !hasSnapshotsToWatch;
            } else {
                // Need to start watching this hierarchy
                return hasSnapshotsToWatch;
            }
        });
    }

    @Override
    protected SnapshotHierarchy doUpdateVfsOnBuildStarted(SnapshotHierarchy root) {
        return movedHierarchyHandler.handleMovedHierarchies(root);
    }

    @Override
    protected void startWatchingHierarchies(Collection<File> hierarchiesToStartWatching) {
        fileWatcher.startWatching(hierarchiesToStartWatching);
    }

    @Override
    protected void stopWatchingHierarchies(Collection<File> hierarchiesToStopWatching) {
        if (!fileWatcher.stopWatching(hierarchiesToStopWatching)) {
            LOGGER.debug("Couldn't stop watching directories: {}", hierarchiesToStopWatching);
        }
    }

    @Override
    protected void startWatchingProbeForHierarchy(File hierarchyToWatch) {
        // No need to start watching anything, probe directory is under the watched hierarchy
    }

    @Override
    protected void stopWatchingProbeForHierarchy(File hierarchyToWatch) {
        // No need to stop watching anything, probe directory is under the watched hierarchy
    }

    @Override
    protected WatchableHierarchies.Invalidator createInvalidator() {
        return (location, currentRoot) -> currentRoot.invalidate(location, SnapshotHierarchy.NodeDiffListener.NOOP);
    }

    public interface MovedHierarchyHandler {
        /**
         * On Windows when watched hierarchies are moved, the OS does not send a notification,
         * even though the VFS should be updated. Our best bet here is to cull any moved watch
         * roots from the VFS at the start of every build.
         */
        SnapshotHierarchy handleMovedHierarchies(SnapshotHierarchy root);
    }
}
