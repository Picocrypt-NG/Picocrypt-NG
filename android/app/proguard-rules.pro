# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# ============================================================================
# Preserve stack traces and line numbers for crash reporting
# ============================================================================
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# ============================================================================
# Kotlin metadata for reflection
# ============================================================================
-keepattributes *Annotation*
-keepattributes Signature
-keepattributes InnerClasses
-keepattributes EnclosingMethod

# ============================================================================
# Go Mobile bindings - keep entire mobile package
# ============================================================================
-keep class mobile.** { *; }
-keepclassmembers class mobile.** { *; }
-dontwarn mobile.**

# ============================================================================
# Native methods (JNI) - required for Go Mobile bindings
# ============================================================================
-keepclasseswithmembernames class * {
    native <methods>;
}

# ============================================================================
# Kotlin Parcelize - keep Parcelable classes and their CREATOR fields
# ============================================================================
-keep class io.github.picocrypt_ng.FormData { *; }
-keep class io.github.picocrypt_ng.KeyfileInfo { *; }
-keep class io.github.picocrypt_ng.DecryptionInfo { *; }

# Keep Parcelable implementation
-keep class * implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator *;
}

# Keep Parcelize generated code
-keepclassmembers class * implements android.os.Parcelable {
    static ** CREATOR;
}

# ============================================================================
# ViewModels - keep for SavedStateHandle and lifecycle
# ============================================================================
-keep class io.github.picocrypt_ng.MainViewModel { *; }
-keep class io.github.picocrypt_ng.OperationViewModel { *; }
-keep class * extends androidx.lifecycle.ViewModel {
    <init>(...);
}

# Keep ViewModel constructors
-keepclassmembers class * extends androidx.lifecycle.ViewModel {
    <init>(...);
}

# ============================================================================
# JSON classes (org.json) - used in GoBridge
# ============================================================================
-keep class org.json.** { *; }
-keepclassmembers class org.json.** { *; }

# ============================================================================
# Coroutines - keep coroutine-related classes
# ============================================================================
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-keepclassmembers class kotlinx.coroutines.** {
    volatile <fields>;
}

# ============================================================================
# Compose - additional rules if needed (default rules should cover most)
# ============================================================================
# Compose BOM typically includes ProGuard rules, but keep these for safety
-keep class androidx.compose.** { *; }
-keepclassmembers class androidx.compose.** { *; }

# ============================================================================
# Keep application classes
# ============================================================================
-keep class io.github.picocrypt_ng.MainActivity { *; }
-keep class io.github.picocrypt_ng.GoBridge { *; }
-keep class io.github.picocrypt_ng.OperationManager { *; }
-keep class io.github.picocrypt_ng.FileCopyService { *; }
-keep class io.github.picocrypt_ng.OperationNotificationService { *; }
-keep class io.github.picocrypt_ng.AppError { *; }
-keep class io.github.picocrypt_ng.OperationState { *; }

# ============================================================================
# Keep data classes used in StateFlow and other reactive components
# ============================================================================
-keep class io.github.picocrypt_ng.EncryptOptions { *; }
-keep class io.github.picocrypt_ng.DecryptOptions { *; }
-keep class io.github.picocrypt_ng.ProgressState { *; }