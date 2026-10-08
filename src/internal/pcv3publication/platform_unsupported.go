//go:build !linux && !darwin && !windows

package pcv3publication

func nativeOperations() platformOperations {
	return platformOperations{}
}
