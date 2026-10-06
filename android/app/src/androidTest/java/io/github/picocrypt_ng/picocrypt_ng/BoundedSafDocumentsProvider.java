package io.github.picocrypt_ng.picocrypt_ng;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.os.SystemClock;
import android.provider.DocumentsContract;
import android.provider.DocumentsProvider;
import android.system.ErrnoException;
import android.system.Os;
import android.system.StructStat;
import android.net.Uri;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayDeque;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/** Test-APK-only provider: real Binder, cursors and FDs; no app-owned Kotlin runtime. */
public final class BoundedSafDocumentsProvider extends DocumentsProvider {
    public static final String AUTHORITY = "io.github.picocrypt_ng.picocrypt_ng.test.bounded";
    public static final String TARGET_PACKAGE = "io.github.picocrypt_ng.picocrypt_ng";
    public static final Uri tree = DocumentsContract.buildTreeDocumentUri(AUTHORITY, "root");
    private static final String[] COLUMNS = {
        DocumentsContract.Document.COLUMN_DOCUMENT_ID, DocumentsContract.Document.COLUMN_DISPLAY_NAME,
        DocumentsContract.Document.COLUMN_MIME_TYPE, DocumentsContract.Document.COLUMN_SIZE,
        DocumentsContract.Document.COLUMN_FLAGS
    };

    private File root;
    private int creations;
    private int failAfter = Integer.MAX_VALUE;
    private long foreignDevice;
    private long foreignInode;
    private String idPadding = "";
    private volatile String blockedSource;
    private volatile CountDownLatch sourceRelease = new CountDownLatch(0);
    private final AtomicInteger sourceOpens = new AtomicInteger();
    private volatile boolean sourceBlocked;
    private volatile String blockedMetadata;
    private volatile CountDownLatch metadataRelease = new CountDownLatch(0);
    private volatile boolean metadataBlocked;

    @Override public boolean onCreate() {
        root = new File(getContext().getCacheDir(), "bounded-saf-provider");
        return true;
    }

    @Override public Bundle call(String method, String arg, Bundle extras) {
        if (!method.startsWith("bounded-test-")) return super.call(method, arg, extras);
        require(TARGET_PACKAGE.equals(getCallingPackage()), "Unexpected provider caller");
        try {
            switch (method) {
                case "bounded-test-reset": {
                    sourceRelease.countDown();
                    metadataRelease.countDown();
                    require(!root.exists() || deleteTree(root), "Provider root cleanup failed");
                    require(root.mkdir(), "Provider root creation failed");
                    File foreign = new File(root, "untouched");
                    write(foreign, "foreign data must survive");
                    StructStat identity = Os.stat(foreign.getPath());
                    foreignDevice = identity.st_dev;
                    foreignInode = identity.st_ino;
                    creations = 0;
                    blockedSource = null;
                    sourceBlocked = false;
                    blockedMetadata = null;
                    metadataBlocked = false;
                    sourceOpens.set(0);
                    failAfter = extras == null ? Integer.MAX_VALUE : extras.getInt("failAfter", Integer.MAX_VALUE);
                    int padding = extras == null ? 0 : extras.getInt("idPaddingBytes");
                    require(padding >= 0 && padding <= 40_000, "Invalid padding");
                    idPadding = repeat("P", padding);
                    BoundedSafGrantReceiver.grant(getContext());
                    return new Bundle();
                }
                case "bounded-test-verify": {
                    int files = 0, invalid = 0, empty = 0;
                    String firstInvalid = "";
                    int expectedCount = extras.getInt("expectedCount");
                    ArrayDeque<File> pending = new ArrayDeque<>();
                    File payload = new File(root, "payload");
                    if (payload.exists()) pending.add(payload);
                    while (!pending.isEmpty()) {
                        File file = pending.removeFirst();
                        if (file.isDirectory()) {
                            File[] children = file.listFiles();
                            require(children != null, "Provider directory unreadable");
                            for (File child : children) pending.addLast(child);
                        } else if (file.isFile()) {
                            int number = -1;
                            try {
                                if (file.getName().startsWith("f")) number = Integer.parseInt(file.getName().substring(1));
                            } catch (NumberFormatException ignored) { }
                            String body = read(file);
                            boolean allowedEmpty = extras.getBoolean("allowEmpty") && body.isEmpty();
                            if (body.isEmpty()) empty++;
                            String expectedName = String.format(java.util.Locale.ROOT, "f%06d", number);
                            if (number < 0 || number >= expectedCount || !payload.equals(file.getParentFile()) ||
                                    !file.getName().equals(expectedName) ||
                                    (!allowedEmpty && !body.equals("record-" + number + "\n"))) {
                                if (invalid == 0) firstInvalid = file.getName() + " bytes=" + file.length() +
                                    " parentMatches=" + payload.equals(file.getParentFile()) + " number=" + number;
                                invalid++;
                            }
                            files++;
                        }
                    }
                    Bundle result = new Bundle();
                    result.putInt("files", files);
                    result.putInt("invalid", invalid);
                    result.putInt("empty", empty);
                    result.putString("firstInvalid", firstInvalid);
                    result.putInt("creations", creations);
                    File foreign = new File(root, "untouched");
                    StructStat identity = Os.stat(foreign.getPath());
                    result.putBoolean("foreignPreserved", read(foreign).equals("foreign data must survive") &&
                        identity.st_dev == foreignDevice && identity.st_ino == foreignInode);
                    boolean expectedRoots = true;
                    String[] roots = root.list();
                    require(roots != null, "Provider root unreadable");
                    for (String name : roots) expectedRoots &= name.equals("untouched") || name.equals("payload");
                    result.putBoolean("onlyExpectedRoots", expectedRoots);
                    return result;
                }
                case "bounded-test-seed-source": {
                    require(new File(root, "untouched").delete(), "Source sentinel cleanup failed");
                    int count = extras == null ? 0 : extras.getInt("count");
                    require(count >= 0 && count <= 4097, "Invalid source count");
                    if (count == 0) {
                        require(new File(root, "sub").mkdir(), "Source folder creation failed");
                        write(new File(root, "a.txt"), "a");
                        write(new File(root, "sub/b.txt"), "b");
                    } else {
                        for (int i = 0; i < count; i++) write(new File(root, "source-" + i + ".txt"), "source " + i);
                    }
                    if (extras != null && extras.getBoolean("encodedIds")) idPadding = repeat(" /%Ж😀x", 4000);
                    return new Bundle();
                }
                case "bounded-test-block-source":
                    require(arg != null, "Missing source gate ID");
                    blockedSource = arg;
                    sourceRelease = new CountDownLatch(1);
                    return new Bundle();
                case "bounded-test-source-state": {
                    Bundle result = new Bundle();
                    result.putBoolean("blocked", sourceBlocked);
                    result.putInt("opens", sourceOpens.get());
                    result.putBoolean("metadataBlocked", metadataBlocked);
                    return result;
                }
                case "bounded-test-release-source":
                    sourceRelease.countDown();
                    return new Bundle();
                case "bounded-test-block-metadata":
                    require(arg != null, "Missing metadata gate ID");
                    blockedMetadata = arg;
                    metadataRelease = new CountDownLatch(1);
                    return new Bundle();
                case "bounded-test-release-metadata":
                    metadataRelease.countDown();
                    return new Bundle();
                case "bounded-test-cleanup": {
                    sourceRelease.countDown();
                    metadataRelease.countDown();
                    Bundle result = new Bundle();
                    result.putBoolean("cleaned", deleteTree(root));
                    return result;
                }
                default: throw new IllegalArgumentException("Unknown test provider command");
            }
        } catch (IOException | ErrnoException failure) {
            throw new IllegalStateException("Test provider filesystem failure", failure);
        }
    }

    @Override public Cursor queryRoots(String[] projection) {
        MatrixCursor cursor = new MatrixCursor(projection == null ? new String[] {
            DocumentsContract.Root.COLUMN_ROOT_ID, DocumentsContract.Root.COLUMN_DOCUMENT_ID
        } : projection);
        MatrixCursor.RowBuilder row = cursor.newRow();
        row.add(DocumentsContract.Root.COLUMN_ROOT_ID, "root");
        row.add(DocumentsContract.Root.COLUMN_DOCUMENT_ID, "root");
        return cursor;
    }

    @Override public Cursor queryDocument(String documentId, String[] projection) throws FileNotFoundException {
        if (unpadded(documentId).equals(blockedMetadata)) {
            metadataBlocked = true;
            try {
                if (!metadataRelease.await(20, TimeUnit.SECONDS)) throw new FileNotFoundException("Metadata gate timed out");
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new FileNotFoundException("Metadata gate interrupted");
            }
        }
        MatrixCursor cursor = new MatrixCursor(projection == null ? COLUMNS : projection);
        row(cursor, documentId);
        return cursor;
    }

    @Override public Cursor queryChildDocuments(String parentId, String[] projection, String sortOrder) throws FileNotFoundException {
        MatrixCursor cursor = new MatrixCursor(projection == null ? COLUMNS : projection);
        File[] children = file(parentId).listFiles();
        if (children != null) for (File child : children) row(cursor, id(child));
        return cursor;
    }

    @Override public boolean isChildDocument(String parentId, String documentId) {
        try {
            return file(documentId).getCanonicalPath().startsWith(file(parentId).getCanonicalPath() + File.separator);
        } catch (IOException failure) { throw new IllegalStateException(failure); }
    }

    @Override public String createDocument(String parentId, String mimeType, String name) throws FileNotFoundException {
        if (creations >= failAfter) throw new FileNotFoundException("Test provider create failure");
        require(!name.equals(".") && !name.equals("..") && name.indexOf('/') < 0 && name.indexOf('\\') < 0, "Unsafe name");
        File child = new File(file(parentId), name);
        try {
            boolean created = DocumentsContract.Document.MIME_TYPE_DIR.equals(mimeType) ? child.mkdir() : child.createNewFile();
            if (!created) throw new FileNotFoundException("Test provider refuses replacement");
        } catch (IOException failure) {
            FileNotFoundException wrapped = new FileNotFoundException("Test provider create failure");
            wrapped.initCause(failure);
            throw wrapped;
        }
        creations++;
        return id(child);
    }

    @Override public ParcelFileDescriptor openDocument(String documentId, String mode, CancellationSignal signal) throws FileNotFoundException {
        if (signal != null) signal.throwIfCanceled();
        if (mode.equals("r")) {
            sourceOpens.incrementAndGet();
            if (unpadded(documentId).equals(blockedSource)) {
                sourceBlocked = true;
                try {
                    if (!sourceRelease.await(20, TimeUnit.SECONDS)) throw new FileNotFoundException("Source gate timed out");
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new FileNotFoundException("Source gate interrupted");
                }
                if (signal != null) signal.throwIfCanceled();
            }
        }
        return ParcelFileDescriptor.open(file(documentId), ParcelFileDescriptor.parseMode(mode));
    }

    private String unpadded(String id) { return id.startsWith(idPadding) ? id.substring(idPadding.length()) : id; }
    private File file(String documentId) {
        String id = unpadded(documentId);
        File candidate = id.equals("root") ? root : new File(root, id.startsWith("root/") ? id.substring(5) : id);
        try {
            File canonical = candidate.getCanonicalFile();
            String path = root.getCanonicalPath();
            require(canonical.getPath().equals(path) || canonical.getPath().startsWith(path + File.separator), "Escaped provider root");
            return candidate;
        } catch (IOException failure) { throw new IllegalStateException(failure); }
    }
    private String id(File file) { return idPadding + "root/" + root.toPath().relativize(file.toPath()).toString(); }
    private void row(MatrixCursor cursor, String documentId) throws FileNotFoundException {
        File file = file(documentId);
        if (!file.exists()) throw new FileNotFoundException("Test document missing");
        MatrixCursor.RowBuilder row = cursor.newRow();
        for (String column : cursor.getColumnNames()) {
            Object value;
            switch (column) {
                case DocumentsContract.Document.COLUMN_DOCUMENT_ID: value = documentId; break;
                case DocumentsContract.Document.COLUMN_DISPLAY_NAME: value = file.getName(); break;
                case DocumentsContract.Document.COLUMN_MIME_TYPE: value = file.isDirectory() ? DocumentsContract.Document.MIME_TYPE_DIR : "application/octet-stream"; break;
                case DocumentsContract.Document.COLUMN_SIZE: value = file.length(); break;
                case DocumentsContract.Document.COLUMN_FLAGS: value = file.isDirectory() ? DocumentsContract.Document.FLAG_DIR_SUPPORTS_CREATE : DocumentsContract.Document.FLAG_SUPPORTS_WRITE; break;
                default: value = null;
            }
            row.add(column, value);
        }
    }
    private static String repeat(String value, int count) {
        StringBuilder result = new StringBuilder(value.length() * count);
        for (int i = 0; i < count; i++) result.append(value);
        return result.toString();
    }
    private static String read(File file) throws IOException { return new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8); }
    private static void write(File file, String text) throws IOException { Files.write(file.toPath(), text.getBytes(StandardCharsets.UTF_8)); }
    private static boolean deleteTree(File file) {
        File[] children = file.listFiles();
        if (children != null) for (File child : children) if (!deleteTree(child)) return false;
        return !file.exists() || file.delete();
    }
    private static void require(boolean condition, String message) { if (!condition) throw new IllegalStateException(message); }

    public static void grantAccessForTest(Context context) {
        ComponentName receiver = new ComponentName(TARGET_PACKAGE + ".test", BoundedSafGrantReceiver.class.getName());
        context.sendBroadcast(new Intent(AUTHORITY + ".GRANT").setComponent(receiver));
        long deadline = SystemClock.uptimeMillis() + 5000;
        while (context.checkUriPermission(tree, Process.myPid(), Process.myUid(),
                Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION) != PackageManager.PERMISSION_GRANTED) {
            require(SystemClock.uptimeMillis() < deadline, "Test provider URI grant was not delivered");
            SystemClock.sleep(10);
        }
    }
}
