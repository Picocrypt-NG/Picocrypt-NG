//go:build pcv3_calibration

package pcv3credential

import (
	"Picocrypt-NG/internal/crypto"
	"context"
	"errors"
)

// CalibrationProbeStatus is a bounded, non-secret terminal observation from
// the default-excluded fixed-profile calibration probe.
type CalibrationProbeStatus uint8

const (
	CalibrationProbeStatusUnknown CalibrationProbeStatus = iota
	CalibrationProbeStatusCompleted
	CalibrationProbeStatusCancelled
	CalibrationProbeStatusFailed
)

type calibrationProbeAdmitter struct{}

func (calibrationProbeAdmitter) AdmitKDF(
	ctx context.Context,
	profile KDFProfile,
) (KDFAdmission, error) {
	if ctx == nil || ctx.Err() != nil {
		return KDFAdmissionDeniedUnknown, nil
	}
	expected, err := fixedProfileForSuite(SuiteParanoid1)
	if err != nil || profile != expected {
		return KDFAdmissionDeniedUnknown, nil
	}
	return KDFAdmissionGranted, nil
}

// RunCalibrationProbe runs the exact production Paranoid-1 KDF path over
// fixed public bytes. It accepts no credential, factor, file, volume, profile,
// salt, or resource-policy input and returns no derived material.
func RunCalibrationProbe(ctx context.Context) (status CalibrationProbeStatus) {
	status = CalibrationProbeStatusFailed
	input := [credentialInputBytes]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	}
	salt := [kdfSaltBytes]byte{
		0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
		0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
	}
	defer crypto.SecureZeroMultiple(input[:], salt[:])
	defer func() {
		if recover() != nil {
			status = CalibrationProbeStatusFailed
		}
	}()

	secret, err := runFixedProfileKDFBorrowed(
		ctx,
		input[:],
		salt[:],
		SuiteParanoid1,
		calibrationProbeAdmitter{},
		deriveArgon2ID,
	)
	if secret != nil {
		defer secret.Close()
	}
	if err == nil && secret != nil {
		return CalibrationProbeStatusCompleted
	}
	var kdfErr *KDFError
	if errors.As(err, &kdfErr) && kdfErr.Code == KDFErrorCancelled {
		return CalibrationProbeStatusCancelled
	}
	return CalibrationProbeStatusFailed
}
