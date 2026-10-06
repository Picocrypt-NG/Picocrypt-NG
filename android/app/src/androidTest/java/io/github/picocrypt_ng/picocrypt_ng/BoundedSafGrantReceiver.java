package io.github.picocrypt_ng.picocrypt_ng;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Runs as the provider-owning test APK and grants only its synthetic tree. */
public final class BoundedSafGrantReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        if (!(BoundedSafDocumentsProvider.AUTHORITY + ".GRANT").equals(intent.getAction())) {
            throw new IllegalArgumentException("Unexpected grant action");
        }
        grant(context);
    }

    static void grant(Context context) {
        context.grantUriPermission(BoundedSafDocumentsProvider.TARGET_PACKAGE, BoundedSafDocumentsProvider.tree,
            Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION |
                Intent.FLAG_GRANT_PREFIX_URI_PERMISSION);
    }
}
