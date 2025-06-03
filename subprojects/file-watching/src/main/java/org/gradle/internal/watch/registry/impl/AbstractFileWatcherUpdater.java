/*
 * Copyright 2021 the original author or authors.
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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableSet;
import org.gradle.internal.file.FileHierarchySet;
import org.gradle.internal.file.FileMetadata;
import org.gradle.internal.file.FileType;
import org.gradle.internal.snapshot.FileSystemLocationSnapshot;
import org.gradle.internal.snapshot.SnapshotHierarchy;
import org.gradle.internal.watch.registry.FileWatcherProbeRegistry;
import org.gradle.internal.watch.registry.FileWatcherUpdater;
import org.gradle.internal.watch.vfs.WatchMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.CheckReturnValue;
import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public abstract class AbstractFileWatcherUpdater implements FileWatcherUpdater {
    private static final Logger LOGGER = LoggerFactory.getLogger(AbstractFileWatcherUpdater.class);

    private final FileSystemLocationToWatchValidator locationToWatchValidator;
    protected final FileWatcherProbeRegistry probeRegistry;
    protected final WatchableHierarchies watchableHierarchies;
    protected FileHierarchySet watchedFiles = FileHierarchySet.empty();
    private ImmutableSet<File> watchedHierarchies = ImmutableSet.of();
    private ImmutableSet<File> probedHierarchies = ImmutableSet.of();

    public AbstractFileWatcherUpdater(
        FileSystemLocationToWatchValidator locationToWatchValidator,
        FileWatcherProbeRegistry probeRegistry,
        WatchableHierarchies watchableHierarchies
    ) {
        this.locationToWatchValidator = locationToWatchValidator;
        this.probeRegistry = probeRegistry;
        this.watchableHierarchies = watchableHierarchies;
    }

    @Override
    public void registerWatchableHierarchy(File watchableHierarchy, SnapshotHierarchy root) {
        watchableHierarchies.registerWatchableHierarchy(watchableHierarchy, root);
        probeRegistry.registerProbe(watchableHierarchy);
        updateWatchedHierarchies(root);
    }

    @Override
    public final SnapshotHierarchy updateVfsOnBuildStarted(SnapshotHierarchy root, WatchMode watchMode) {
        watchableHierarchies.updateUnsupportedFileSystems(watchMode);
        SnapshotHierarchy newRoot = watchableHierarchies.removeUnwatchableContentOnBuildStart(root, createInvalidator());
        newRoot = doUpdateVfsOnBuildStarted(newRoot);
        if (root != newRoot) {
            updateWatchedHierarchies(newRoot);
        }
        return newRoot;
    }

    @CheckReturnValue
    protected abstract SnapshotHierarchy doUpdateVfsOnBuildStarted(SnapshotHierarchy root);

    @Override
    public void virtualFileSystemContentsChanged(Collection<FileSystemLocationSnapshot> removedSnapshots, Collection<FileSystemLocationSnapshot> addedSnapshots, SnapshotHierarchy root) {
        boolean contentsChanged = handleVirtualFileSystemContentsChanged(removedSnapshots, addedSnapshots, root);
        if (contentsChanged) {
            updateWatchedHierarchies(root);
        }
    }

    protected abstract boolean handleVirtualFileSystemContentsChanged(Collection<FileSystemLocationSnapshot> removedSnapshots, Collection<FileSystemLocationSnapshot> addedSnapshots, SnapshotHierarchy root);

    @Override
    public SnapshotHierarchy updateVfsOnBuildFinished(SnapshotHierarchy root, WatchMode watchMode, int maximumNumberOfWatchedHierarchies) {
        SnapshotHierarchy newRoot = watchableHierarchies.removeUnwatchableContentOnBuildFinished(
            root,
            watchMode,
            watchedFiles::contains,
            maximumNumberOfWatchedHierarchies,
            createInvalidator()
        );

        if (root != newRoot) {
            updateWatchedHierarchies(newRoot);
        }
        LOGGER.info("Watched directory hierarchies: {}", watchedHierarchies);
        return newRoot;
    }

    @Override
    public Collection<File> getWatchedHierarchies() {
        return watchedHierarchies;
    }

    @Override
    public FileHierarchySet getWatchedFiles() {
        return watchedFiles;
    }

    @Override
    public void triggerWatchProbe(String path) {
        probeRegistry.triggerWatchProbe(path);
    }

    protected abstract WatchableHierarchies.Invalidator createInvalidator();

    private void updateWatchedHierarchies(SnapshotHierarchy root) {
        ImmutableSet<File> oldWatchedHierarchies = watchedHierarchies;
        ImmutableSet<File> oldProbedHierarchies = probedHierarchies;

        watchedFiles = resolveWatchedFiles(watchableHierarchies, root);

        ImmutableSet.Builder<File> watchedHierarchiesBuilder = ImmutableSet.builder();
        watchedFiles.visitRoots(absolutePath -> watchedHierarchiesBuilder.add(new File(absolutePath)));
        watchedHierarchies = watchedHierarchiesBuilder.build();

        // Probe every hierarchy that is watched, even ones nested inside others
        probedHierarchies = watchableHierarchies.stream()
            .filter(watchedFiles::contains)
            .collect(ImmutableSet.toImmutableSet());

        if (oldWatchedHierarchies.equals(watchedHierarchies) && oldProbedHierarchies.equals(probedHierarchies)) {
            // Nothing changed
            return;
        }

        if (watchedHierarchies.isEmpty()) {
            LOGGER.info("Not watching anything anymore");
        }
        List<File> hierarchiesToStopWatching = oldWatchedHierarchies.stream()
            .filter(oldWatchedHierarchy -> !watchedHierarchies.contains(oldWatchedHierarchy))
            .collect(Collectors.toCollection(() -> new ArrayList<>(oldWatchedHierarchies.size())));
        List<File> hierarchiesToStartWatching = watchedHierarchies.stream()
            .filter(newWatchedHierarchy -> !oldWatchedHierarchies.contains(newWatchedHierarchy))
            .collect(Collectors.toCollection(() -> new ArrayList<>(watchedHierarchies.size())));

        oldProbedHierarchies.stream()
            .filter(oldProbedHierarchy -> !probedHierarchies.contains(oldProbedHierarchy))
            .forEach(probedHierarchy -> {
                stopWatchingProbeForHierarchy(probedHierarchy);
                probeRegistry.disarmWatchProbe(probedHierarchy);
            });

        if (!hierarchiesToStopWatching.isEmpty()) {
            stopWatchingHierarchies(hierarchiesToStopWatching);
        }
        if (!hierarchiesToStartWatching.isEmpty()) {
            hierarchiesToStartWatching.forEach(locationToWatchValidator::validateLocationToWatch);
            startWatchingHierarchies(hierarchiesToStartWatching);
        }

        probedHierarchies.stream()
            .filter(newProbedHierarchy -> !oldProbedHierarchies.contains(newProbedHierarchy))
            .forEach(probedHierarchy -> {
                startWatchingProbeForHierarchy(probedHierarchy);
                probeRegistry.armWatchProbe(probedHierarchy);
            });

        LOGGER.info("Watching {} directory hierarchies to track changes", watchedHierarchies.size());
    }

    protected abstract void startWatchingHierarchies(Collection<File> hierarchiesToWatch);

    protected abstract void startWatchingProbeForHierarchy(File hierarchyToWatch);

    protected abstract void stopWatchingHierarchies(Collection<File> hierarchiesToWatch);

    protected abstract void stopWatchingProbeForHierarchy(File hierarchyToWatch);

    public interface FileSystemLocationToWatchValidator {
        FileSystemLocationToWatchValidator NO_VALIDATION = location -> {
        };

        void validateLocationToWatch(File location);
    }

    @VisibleForTesting
    static FileHierarchySet resolveWatchedFiles(WatchableHierarchies watchableHierarchies, SnapshotHierarchy vfsRoot) {
        return watchableHierarchies.stream()
            .map(File::getPath)
            .filter(watchableHierarchy -> hasWatchableContent(vfsRoot.rootSnapshotsUnder(watchableHierarchy), watchableHierarchies))
            .reduce(FileHierarchySet.empty(), FileHierarchySet::plus, Combiners.nonCombining());
    }

    private static boolean hasWatchableContent(Stream<FileSystemLocationSnapshot> snapshots, WatchableHierarchies watchableHierarchies) {
        return snapshots
            .anyMatch(snapshot -> !isMissing(snapshot) && !watchableHierarchies.ignoredForWatching(snapshot));
    }

    private static boolean isMissing(FileSystemLocationSnapshot snapshot) {
        // Missing accessed indirectly means we have a dangling symlink in the directory, and that's content we cannot ignore
        return snapshot.getType() == FileType.Missing && snapshot.getAccessType() == FileMetadata.AccessType.DIRECT;
    }
}
