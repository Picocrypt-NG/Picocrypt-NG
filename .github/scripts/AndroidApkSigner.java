import com.android.apksigner.ApkSignerTool;

/** Keeps the selected key alias out of the operating system's command line. */
public final class AndroidApkSigner {
    public static void main(String[] args) throws Exception {
        String alias = System.getenv("ANDROID_KEY_ALIAS");
        if (args.length != 3 || alias == null || alias.isEmpty()) {
            System.err.println("APK signing requires a keystore, output, input, and key alias.");
            System.exit(2);
        }
        ApkSignerTool.main(new String[] {
            "sign", "--ks", args[0], "--ks-key-alias", alias,
            "--ks-pass", "env:ANDROID_KEYSTORE_PASSWORD",
            "--key-pass", "env:ANDROID_KEY_PASSWORD",
            "--v1-signing-enabled", "false", "--v4-signing-enabled", "false",
            "--alignment-preserved", "true",
            "--out", args[1], args[2],
        });
    }
}
