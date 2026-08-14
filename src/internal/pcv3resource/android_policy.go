package pcv3resource

// androidReadPolicyProvider is an optional, package-owned presentation seam.
// It reports only whether a frozen Android read policy is configured; it must
// not observe volatile resource facts or make a KDF admission decision.
type androidReadPolicyProvider interface {
	AndroidReadPolicyConfigured() bool
}

func androidReadPolicyConfigured(provider snapshotProvider) bool {
	configuredProvider, ok := provider.(androidReadPolicyProvider)
	return ok && configuredProvider.AndroidReadPolicyConfigured()
}

// AndroidReadPolicyConfigured reports whether the native Android provider has
// an explicitly frozen read policy. It grants no resource or operation
// authority; each PCV3 start still performs a fresh KDF admission.
func AndroidReadPolicyConfigured() bool {
	return androidReadPolicyConfigured(newPlatformSnapshotProvider())
}
