package mobile

import (
	"Picocrypt-NG/internal/pcv3operation"
	"strconv"
)

const pcv3ArtifactInspectionPageMaximum = 128

// pcv3ArtifactInspectionView is the sealed core metadata/page boundary. It
// carries neither a Result nor any path, plaintext, publication, or action
// authority.
type pcv3ArtifactInspectionView interface {
	Metadata() pcv3operation.ArtifactInspectionMetadata
	Page(offset, limit uint64) ([]pcv3operation.ArtifactRange, bool)
}

// PCV3ArtifactInspection is an immutable, passive view of one durable Force
// artifact. It cannot save, remove, reopen, identify, or otherwise act on the
// artifact.
type PCV3ArtifactInspection struct {
	view pcv3ArtifactInspectionView
}

// newPCV3ArtifactInspection is the production core boundary. Keeping its
// concrete pointer type preserves a denied typed-nil core inspection as nil.
func newPCV3ArtifactInspection(inspection *pcv3operation.ArtifactInspection) *PCV3ArtifactInspection {
	if inspection == nil {
		return nil
	}
	return newPCV3ArtifactInspectionFromView(inspection)
}

// newPCV3ArtifactInspectionFromView is an adapter-only seam for immutable
// Metadata/Page conversion tests. Production completion uses the concrete
// core-pointer constructor above.
func newPCV3ArtifactInspectionFromView(view pcv3ArtifactInspectionView) *PCV3ArtifactInspection {
	if view == nil {
		return nil
	}
	return &PCV3ArtifactInspection{view: view}
}

// Kind returns the closed semantic artifact kind.
func (inspection *PCV3ArtifactInspection) Kind() string {
	if inspection == nil || inspection.view == nil {
		return "unknown"
	}
	switch inspection.view.Metadata().Kind {
	case pcv3operation.ArtifactStatePartial:
		return "partial"
	case pcv3operation.ArtifactStateUnverifiedForensic:
		return "unverified-forensic"
	default:
		return "unknown"
	}
}

// Role returns the closed selected physical role, or none for verified/missing
// evidence.
func (inspection *PCV3ArtifactInspection) Role() string {
	if inspection == nil || inspection.view == nil {
		return "unknown"
	}
	switch inspection.view.Metadata().Role {
	case pcv3operation.ArtifactRoleNone:
		return "none"
	case pcv3operation.ArtifactRolePrimary:
		return "primary"
	case pcv3operation.ArtifactRoleBackup:
		return "backup"
	case pcv3operation.ArtifactRoleD1Front:
		return "d1-front"
	case pcv3operation.ArtifactRoleD1Tail:
		return "d1-tail"
	default:
		return "unknown"
	}
}

// PlaintextLength returns the exact unsigned length as a decimal string.
func (inspection *PCV3ArtifactInspection) PlaintextLength() string {
	return strconv.FormatUint(inspection.metadata().PlaintextLength, 10)
}

// FinalStatus returns the closed final-record evidence status.
func (inspection *PCV3ArtifactInspection) FinalStatus() string {
	switch inspection.metadata().Final {
	case pcv3operation.ArtifactFinalVerified:
		return "verified"
	case pcv3operation.ArtifactFinalUnverified:
		return "unverified"
	case pcv3operation.ArtifactFinalMissing:
		return "missing"
	default:
		return "unknown"
	}
}

// RangeCount returns the exact range count as a decimal string.
func (inspection *PCV3ArtifactInspection) RangeCount() string {
	return strconv.FormatUint(inspection.metadata().RangeCount, 10)
}

// VerifiedCount returns the exact verified-range count as a decimal string.
func (inspection *PCV3ArtifactInspection) VerifiedCount() string {
	return strconv.FormatUint(inspection.metadata().VerifiedRangeCount, 10)
}

// UnverifiedCount returns the exact unverified-range count as a decimal string.
func (inspection *PCV3ArtifactInspection) UnverifiedCount() string {
	return strconv.FormatUint(inspection.metadata().UnverifiedRangeCount, 10)
}

// MissingCount returns the exact missing-range count as a decimal string.
func (inspection *PCV3ArtifactInspection) MissingCount() string {
	return strconv.FormatUint(inspection.metadata().MissingRangeCount, 10)
}

func (inspection *PCV3ArtifactInspection) metadata() pcv3operation.ArtifactInspectionMetadata {
	if inspection == nil || inspection.view == nil {
		return pcv3operation.ArtifactInspectionMetadata{}
	}
	return inspection.view.Metadata()
}

// Page returns a bounded path-free page. Offset is decimal-only because
// gomobile transports all uint64 values as strings.
func (inspection *PCV3ArtifactInspection) Page(offsetDecimal string, limit int) *PCV3ArtifactPage {
	if inspection == nil || inspection.view == nil || limit <= 0 || limit > pcv3ArtifactInspectionPageMaximum {
		return nil
	}
	offset, ok := parsePCV3DecimalUint(offsetDecimal)
	if !ok {
		return nil
	}
	ranges, ok := inspection.view.Page(offset, uint64(limit))
	if !ok || len(ranges) == 0 {
		return nil
	}
	return &PCV3ArtifactPage{ranges: append([]pcv3operation.ArtifactRange(nil), ranges...)}
}

func parsePCV3DecimalUint(value string) (uint64, bool) {
	if value == "" {
		return 0, false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, false
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	return parsed, err == nil
}

// PCV3ArtifactPage is one immutable bounded evidence page. It exposes only
// closed status codes and decimal unsigned values.
type PCV3ArtifactPage struct {
	ranges []pcv3operation.ArtifactRange
}

func (page *PCV3ArtifactPage) Count() int {
	if page == nil {
		return 0
	}
	return len(page.ranges)
}

func (page *PCV3ArtifactPage) RecordIndexAt(index int) string {
	if rangeAt, ok := page.rangeAt(index); ok {
		return strconv.FormatUint(rangeAt.RecordIndex, 10)
	}
	return "0"
}

func (page *PCV3ArtifactPage) StartAt(index int) string {
	if rangeAt, ok := page.rangeAt(index); ok {
		return strconv.FormatUint(rangeAt.Start, 10)
	}
	return "0"
}

func (page *PCV3ArtifactPage) EndAt(index int) string {
	if rangeAt, ok := page.rangeAt(index); ok {
		return strconv.FormatUint(rangeAt.End, 10)
	}
	return "0"
}

func (page *PCV3ArtifactPage) StatusAt(index int) string {
	rangeAt, ok := page.rangeAt(index)
	if !ok {
		return "unknown"
	}
	switch rangeAt.Status {
	case pcv3operation.ArtifactRangeVerified:
		return "verified"
	case pcv3operation.ArtifactRangeUnverified:
		return "unverified"
	case pcv3operation.ArtifactRangeMissing:
		return "missing"
	default:
		return "unknown"
	}
}

func (page *PCV3ArtifactPage) rangeAt(index int) (pcv3operation.ArtifactRange, bool) {
	if page == nil || index < 0 || index >= len(page.ranges) {
		return pcv3operation.ArtifactRange{}, false
	}
	return page.ranges[index], true
}
