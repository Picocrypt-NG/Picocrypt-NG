package pcv3

import (
	"testing"
)

func TestDetectPrefix(t *testing.T) {
	if got := DetectPrefix(nil); got != RouteLegacyEligible {
		t.Fatalf("empty prefix route = %v; want legacy eligible", got)
	}

	var short [3]byte
	for value := range 1 << 8 {
		short[0] = byte(value)
		if got := DetectPrefix(short[:1]); got != RouteLegacyEligible {
			t.Fatalf("one-byte prefix %x route = %v; want legacy eligible", short[:1], got)
		}
	}
	for value := range 1 << 16 {
		short[0] = byte(value >> 8)
		short[1] = byte(value)
		if got := DetectPrefix(short[:2]); got != RouteLegacyEligible {
			t.Fatalf("two-byte prefix %x route = %v; want legacy eligible", short[:2], got)
		}
	}
	for value := range 1 << 24 {
		short[0] = byte(value >> 16)
		short[1] = byte(value >> 8)
		short[2] = byte(value)
		if got := DetectPrefix(short[:]); got != RouteLegacyEligible {
			t.Fatalf("three-byte prefix %x route = %v; want legacy eligible", short[:], got)
		}
	}

	discriminator := [4]byte{'P', 'C', 'V', 0}
	if got := DetectPrefix(discriminator[:]); got != RouteNormalPCV {
		t.Fatalf("literal PCV discriminator route = %v; want normal PCV", got)
	}
	withSuffix := append(discriminator[:], 0xff, 'P', 'C', 'V', 0)
	if got := DetectPrefix(withSuffix); got != RouteNormalPCV {
		t.Fatalf("literal PCV discriminator with suffix route = %v; want normal PCV", got)
	}

	// A complete claim is terminal: the byte immediately after the full
	// discriminator is payload, never a routing or version hint.
	for fifth := range 1 << 8 {
		claimed := []byte{'P', 'C', 'V', 0, byte(fifth), 0x03, 0x00}
		if got := DetectPrefix(claimed); got != RouteNormalPCV {
			t.Fatalf("complete claim with fifth byte %#02x route = %v; want terminal normal PCV", fifth, got)
		}
	}

	for position, original := range discriminator {
		for replacement := range 1 << 8 {
			if byte(replacement) == original {
				continue
			}
			mutated := discriminator
			mutated[position] = byte(replacement)
			if got := DetectPrefix(mutated[:]); got != RouteLegacyEligible {
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
		if got := DetectPrefix(prefix); got != RouteLegacyEligible {
			t.Fatalf("long mismatching prefix %x route = %v; want legacy eligible", prefix, got)
		}
	}

	if got := RouteLegacyEligible.String(); got != "legacy-eligible" {
		t.Fatalf("legacy route string = %q", got)
	}
	if got := RouteNormalPCV.String(); got != "normal-pcv" {
		t.Fatalf("normal PCV route string = %q", got)
	}
	if got := Route(255).String(); got != "unknown-route" {
		t.Fatalf("unknown route string = %q", got)
	}
}
