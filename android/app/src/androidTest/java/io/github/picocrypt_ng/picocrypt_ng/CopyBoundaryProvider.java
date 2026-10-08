package io.github.picocrypt_ng.picocrypt_ng;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.res.AssetFileDescriptor;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.provider.OpenableColumns;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.TimeUnit;

/** Synthetic test-APK provider in another process; tests use actual Binder and pipe FDs. */
public final class CopyBoundaryProvider extends ContentProvider {
    public static final String AUTHORITY = "io.github.picocrypt_ng.picocrypt_ng.test.copy";
    public static final Uri URI = Uri.parse("content://" + AUTHORITY + "/source");
    private volatile String metadata = "normal";
    private volatile boolean displayNameOnly;
    private volatile boolean queryCancellable;
    private final AtomicInteger cursorCloses = new AtomicInteger();
    private volatile boolean blockedQuery;
    private volatile boolean queryCancelled;
    private volatile boolean readerClosed;
    private volatile boolean pipeOpened;
    private volatile boolean blockRead;
    private volatile boolean finitePipe;
    private volatile boolean slice;
    private volatile boolean boundedPipe;
    private volatile long assetOffset;
    private volatile long assetLength;
    private volatile boolean shortPrefix;
    private volatile java.io.FileOutputStream heldOutput;
    private volatile CountDownLatch queryRelease = new CountDownLatch(0);
    private volatile ParcelFileDescriptor writer;
    private File source;

    @Override public boolean onCreate() {
        source = new File(getContext().getCacheDir(), "copy-boundary-source");
        return true;
    }

    @Override public Bundle call(String method, String arg, Bundle extras) {
        try {
            switch (method) {
                case "reset":
                    queryRelease.countDown();
                    if (heldOutput != null) heldOutput.close();
                    heldOutput = null;
                    if (writer != null) writer.close();
                    writer = null;
                    metadata = extras == null ? "normal" : extras.getString("metadata", "normal");
                    queryRelease = new CountDownLatch(metadata.equals("block") ? 1 : 0);
                    blockRead = extras != null && extras.getBoolean("blockRead");
                    finitePipe = extras != null && extras.getBoolean("finitePipe");
                    slice = extras != null && extras.getBoolean("slice");
                    boundedPipe = extras != null && extras.getBoolean("boundedPipe");
                    assetOffset = extras == null ? 0 : extras.getLong("assetOffset");
                    assetLength = extras == null ? 100003 : extras.getLong("assetLength", 100003);
                    shortPrefix = extras != null && extras.getBoolean("shortPrefix");
                    displayNameOnly = false;
                    queryCancellable = false;
                    cursorCloses.set(0);
                    blockedQuery = false;
                    queryCancelled = false;
                    readerClosed = false;
                    pipeOpened = false;
                    try (java.io.FileOutputStream out = new java.io.FileOutputStream(source)) {
                        out.write(body());
                    }
                    return new Bundle();
                case "release-query": queryRelease.countDown(); return new Bundle();
                case "state": {
                    Bundle state = new Bundle();
                    state.putBoolean("queryBlocked", blockedQuery);
                    state.putBoolean("displayNameOnly", displayNameOnly);
                    state.putBoolean("queryCancellable", queryCancellable);
                    state.putInt("cursorCloses", cursorCloses.get());
                    state.putBoolean("queryCancelled", queryCancelled);
                    state.putBoolean("pipeOpened", pipeOpened);
                    state.putBoolean("readerClosed", readerClosed);
                    state.putBoolean("sourcePreserved", java.util.Arrays.equals(body(), java.nio.file.Files.readAllBytes(source.toPath())));
                    return state;
                }
                case "cleanup":
                    queryRelease.countDown();
                    if (heldOutput != null) heldOutput.close();
                    heldOutput = null;
                    if (writer != null) writer.close();
                    writer = null;
                    source.delete();
                    return new Bundle();
                default: throw new IllegalArgumentException(method);
            }
        } catch (IOException e) { throw new IllegalStateException(e); }
    }

    public static byte[] body() {
        byte[] value = new byte[192 * 1024 + 17];
        for (int i = 0; i < value.length; i++) value[i] = (byte) (i * 31 + 7);
        return value;
    }

    @Override public Cursor query(Uri uri, String[] projection, String selection, String[] args, String order) {
        return query(uri, projection, selection, args, order, null);
    }

    @Override public Cursor query(Uri uri, String[] projection, String selection, String[] args, String order, CancellationSignal signal) {
        displayNameOnly = projection != null && projection.length == 1 && projection[0].equals(OpenableColumns.DISPLAY_NAME);
        queryCancellable = signal != null;
        if (metadata.equals("block")) {
            if (signal != null) signal.setOnCancelListener(() -> { queryCancelled = true; queryRelease.countDown(); });
            blockedQuery = true;
            try {
                if (!queryRelease.await(10, TimeUnit.SECONDS)) throw new IllegalStateException("Query gate timed out");
            } catch (InterruptedException e) { throw new IllegalStateException(e); }
            if (signal != null) signal.throwIfCanceled();
        }
        if (metadata.equals("throw")) throw new IllegalArgumentException("Synthetic provider failure");
        if (metadata.equals("no-cursor")) return null;
        MatrixCursor cursor = new MatrixCursor(projection == null ? new String[] { OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE } : projection) {
            @Override public void close() { super.close(); cursorCloses.incrementAndGet(); }
        };
        if (metadata.equals("empty")) return cursor;
        Object name = metadata.equals("null") ? null : metadata.equals("oversized") ? new String(new char[8192]).replace('\0', 'x') : "provider-key";
        Object[] row = new Object[cursor.getColumnCount()];
        for (int i = 0; i < row.length; i++) row[i] = cursor.getColumnNames()[i].equals(OpenableColumns.DISPLAY_NAME) ? name : 0L;
        cursor.addRow(row);
        if (metadata.equals("duplicate")) cursor.addRow(row);
        return cursor;
    }

    @Override public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if (boundedPipe && !blockRead) {
            try {
                ParcelFileDescriptor[] pipe = ParcelFileDescriptor.createPipe();
                writer = pipe[1];
                pipeOpened = true;
                int emitted = shortPrefix ? 7 : (int) (assetOffset + assetLength) + (assetOffset == 0 ? 0 : 17);
                new Thread(() -> {
                    try {
                        // Deliberately retain the writer after all declared asset bytes.
                        java.io.FileOutputStream out = new java.io.FileOutputStream(pipe[1].getFileDescriptor());
                        heldOutput = out; // A GC finalizer must not manufacture test EOF.
                        out.write(body(), 0, emitted);
                        out.flush();
                        if (shortPrefix) { out.close(); pipe[1].close(); }
                    } catch (IOException ignored) { }
                }, "copy-boundary-bounded-pipe").start();
                return pipe[0];
            } catch (IOException e) { throw new FileNotFoundException(e.toString()); }
        }
        if (finitePipe) {
            try {
                ParcelFileDescriptor[] pipe = ParcelFileDescriptor.createPipe();
                new Thread(() -> {
                    try (ParcelFileDescriptor.AutoCloseOutputStream out = new ParcelFileDescriptor.AutoCloseOutputStream(pipe[1])) {
                        SystemClock.sleep(30);
                        byte[] bytes = body();
                        for (int offset = 0; offset < bytes.length; offset += 4096) {
                            out.write(bytes, offset, Math.min(4096, bytes.length - offset));
                            SystemClock.sleep(2);
                        }
                    } catch (IOException ignored) { }
                }, "copy-boundary-finite-pipe").start();
                return pipe[0];
            } catch (IOException e) { throw new FileNotFoundException(e.toString()); }
        }
        if (!blockRead) return ParcelFileDescriptor.open(source, ParcelFileDescriptor.MODE_READ_ONLY);
        try {
            ParcelFileDescriptor[] pipe = ParcelFileDescriptor.createPipe();
            writer = pipe[1];
            pipeOpened = true;
            new Thread(() -> {
                // No payload or EOF is sent: only the consumer may settle the blocked read.
                try {
                    StructPollfd poll = new StructPollfd();
                    poll.fd = pipe[1].getFileDescriptor();
                    poll.events = 0;
                    long until = SystemClock.uptimeMillis() + 10000;
                    while (SystemClock.uptimeMillis() < until && writer == pipe[1]) {
                        Os.poll(new StructPollfd[] { poll }, 50);
                        if ((poll.revents & (OsConstants.POLLERR | OsConstants.POLLHUP)) != 0) {
                            readerClosed = true;
                            return;
                        }
                    }
                } catch (Exception ignored) { }
            }, "copy-boundary-pipe-observer").start();
            return pipe[0];
        } catch (IOException e) { throw new FileNotFoundException(e.toString()); }
    }

    @Override public AssetFileDescriptor openAssetFile(Uri uri, String mode) throws FileNotFoundException {
        if (boundedPipe) return new AssetFileDescriptor(openFile(uri, mode), assetOffset, assetLength);
        if (slice) return new AssetFileDescriptor(ParcelFileDescriptor.open(source, ParcelFileDescriptor.MODE_READ_ONLY), 13, 100003);
        return super.openAssetFile(uri, mode);
    }

    @Override public String getType(Uri uri) { return "application/octet-stream"; }
    @Override public Uri insert(Uri uri, ContentValues values) { throw new UnsupportedOperationException(); }
    @Override public int update(Uri uri, ContentValues values, String selection, String[] args) { throw new UnsupportedOperationException(); }
    @Override public int delete(Uri uri, String selection, String[] args) { throw new UnsupportedOperationException(); }
}
