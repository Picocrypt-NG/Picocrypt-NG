package pcv3_test

import (
	"Picocrypt-NG/internal/pcv3"
	"testing"
)

func TestDetectPrefix(t *testing.T) {
	if got := pcv3.DetectPrefix(nil); got != pcv3.RouteLegacyEligible {
		t.Fatalf("empty prefix route = %v; want legacy eligible", got)
	}

	var short [3]byte
	for value := range 1 << 8 {
		short[0] = byte(value)
		if got := pcv3.DetectPrefix(short[:1]); got != pcv3.RouteLegacyEligible {
			t.Fatalf("one-byte prefix %x route = %v; want legacy eligible", short[:1], got)
		}
	}
	for value := range 1 << 16 {
		short[0] = byte(value >> 8)
		short[1] = byte(value)
		if got := pcv3.DetectPrefix(short[:2]); got != pcv3.RouteLegacyEligible {
			t.Fatalf("two-byte prefix %x route = %v; want legacy eligible", short[:2], got)
		}
	}
	for value := range 1 << 24 {
		short[0] = byte(value >> 16)
		short[1] = byte(value >> 8)
		short[2] = byte(value)
		if got := pcv3.DetectPrefix(short[:]); got != pcv3.RouteLegacyEligible {
			t.Fatalf("three-byte prefix %x route = %v; want legacy eligible", short[:], got)
		}
	}

	discriminator := [4]byte{'P', 'C', 'V', 0}
	if got := pcv3.DetectPrefix(discriminator[:]); got != pcv3.RouteNormalPCV {
		t.Fatalf("literal PCV discriminator route = %v; want normal PCV", got)
	}
	withSuffix := append(discriminator[:], 0xff, 'P', 'C', 'V', 0)
	if got := pcv3.DetectPrefix(withSuffix); got != pcv3.RouteNormalPCV {
		t.Fatalf("literal PCV discriminator with suffix route = %v; want normal PCV", got)
	}

	for position, original := range discriminator {
		for replacement := range 1 << 8 {
			if byte(replacement) == original {
				continue
			}
			mutated := discriminator
			mutated[position] = byte(replacement)
			if got := pcv3.DetectPrefix(mutated[:]); got != pcv3.RouteLegacyEligible {
				t.Fatalf("single-byte mutation at %d (%x) route = %v; want legacy eligible", position, mutated, got)
			}
		}
	}

	for _, prefix := range [][]byte{
		{'X', 'C', 'V', 0, 'P', 'C', 'V', 0},
		{'P', 'X', 'V', 0, 0, 0, 0, 0},
		{'P', 'C', 'X', 0, 'P', 'C', 'V', 0},
		{'P', 'C', 'V', 1, 'P', 'C', 'V', 0},
	} {
		if got := pcv3.DetectPrefix(prefix); got != pcv3.RouteLegacyEligible {
			t.Fatalf("long mismatching prefix %x route = %v; want legacy eligible", prefix, got)
		}
	}

	if got := pcv3.RouteLegacyEligible.String(); got != "legacy-eligible" {
		t.Fatalf("legacy route string = %q", got)
	}
	if got := pcv3.RouteNormalPCV.String(); got != "normal-pcv" {
		t.Fatalf("normal PCV route string = %q", got)
	}
	if got := pcv3.Route(255).String(); got != "unknown-route" {
		t.Fatalf("unknown route string = %q", got)
	}
}
