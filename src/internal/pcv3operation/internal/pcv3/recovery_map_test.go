package pcv3

import "Picocrypt-NG/internal/pcv3operation/internal/pcv3ranges"

// Test-only conversion keeps literal canonical arrays as independent oracles.
// Production code never materializes a full recovery map.
func testRecoveryMap(ranges []RecoveryRange) *pcv3ranges.Map {
	if ranges == nil {
		return nil
	}
	length := uint64(0)
	if len(ranges) > 0 {
		length = ranges[len(ranges)-1].end
	}
	b, err := pcv3ranges.NewBuilder(length, nil)
	if err != nil {
		panic(err)
	}
	defer b.Close()
	for i, r := range ranges {
		start := uint64(i) * 1048576
		end := start + 1048576
		if end > length {
			end = length
		}
		if r.recordIndex != uint64(i) || r.start != start || r.end != end {
			return nil
		}
		if err = b.Append(pcv3ranges.State(r.state)); err != nil {
			return nil
		}
	}
	m, err := b.Seal()
	if err != nil {
		return nil
	}
	return m
}

func testRecoveryRanges(m *pcv3ranges.Map) []RecoveryRange {
	if m == nil {
		return nil
	}
	var result []RecoveryRange
	for r := range m.All() {
		result = append(result, recoveryRangeFromMap(r))
	}
	return result
}
