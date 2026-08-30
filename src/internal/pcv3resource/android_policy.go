package pcv3resource

// androidReadPolicyProvider is an optional package-owned presentation seam.
// It reports whether this build can perform operation-level Android admission;
// it does not grant an operation or cache volatile resource facts.
type androidReadPolicyProvider interface {
	AndroidReadPolicyConfigured() bool
}

func androidReadPolicyConfigured(provider snapshotProvider) bool {
	configuredProvider, ok := provider.(androidReadPolicyProvider)
	return ok && configuredProvider.AndroidReadPolicyConfigured()
}

// AndroidReadPolicyConfigured reports whether the native Android provider can
// perform fresh runtime admission. It grants no operation authority.
func AndroidReadPolicyConfigured() bool {
	return androidReadPolicyConfigured(newPlatformSnapshotProvider())
}
