package pcv3

import (
	"Picocrypt-NG/internal/pcv3governance"
	"Picocrypt-NG/internal/pcv3publication"
	"context"
	"errors"
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

func TestD1ExplicitRoute(t *testing.T) {
	composerCalls := 0
	composer := func(context.Context) (pcv3publication.Result, error) {
		composerCalls++
		return nil, nil
	}

	tests := []struct {
		name          string
		request       *d1RouteRequest
		authorization *pcv3governance.EmissionAuthorization
	}{
		{name: "nil request"},
		{name: "zero mode", request: &d1RouteRequest{sourcePath: "source", destinationPath: "destination"}},
		{name: "unknown mode", request: &d1RouteRequest{mode: d1RouteMode(0xff), sourcePath: "source", destinationPath: "destination"}},
		{name: "empty source", request: &d1RouteRequest{mode: d1RouteExplicit, destinationPath: "destination"}},
		{name: "empty destination", request: &d1RouteRequest{mode: d1RouteExplicit, sourcePath: "source"}},
		{name: "same identity", request: &d1RouteRequest{mode: d1RouteExplicit, sourcePath: "same", destinationPath: "same"}},
		{name: "nil authorization", request: &d1RouteRequest{mode: d1RouteExplicit, sourcePath: "source", destinationPath: "destination"}},
		{name: "zero authorization", request: &d1RouteRequest{mode: d1RouteExplicit, sourcePath: "source", destinationPath: "destination"}, authorization: &pcv3governance.EmissionAuthorization{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := routeExplicitD1(
				context.Background(),
				test.authorization,
				test.request,
				composer,
			)
			if result != nil {
				t.Fatalf("route refusal returned publication result %v", result)
			}
			var failure Failure
			if !errors.As(err, &failure) ||
				failure.Outcome() != OutcomeUnsupportedRoutingPreKDF ||
				failure.Stage() != StageRouting {
				t.Fatalf("route refusal = %T %v; want closed routing failure", err, err)
			}
		})
	}

	if composerCalls != 0 {
		t.Fatalf("refused routes invoked composer %d times", composerCalls)
	}
	if got := DetectPrefix([]byte("PCVOUT3\x00")); got != RouteLegacyEligible {
		t.Fatalf("D1 marker prefix route = %v; want legacy eligible", got)
	}
}

func TestD1WriterRefusalHasNoStageFactorEntropyOrSourceRead(t *testing.T) {
	effects := struct {
		stage, factor, entropy, source, destination int
	}{}
	composer := func(context.Context) (pcv3publication.Result, error) {
		effects.stage++
		effects.factor++
		effects.entropy++
		effects.source++
		effects.destination++
		return nil, nil
	}
	request := &d1RouteRequest{
		mode:            d1RouteExplicit,
		sourcePath:      "ordinary-source",
		destinationPath: "ordinary-destination",
	}

	for _, authorization := range []*pcv3governance.EmissionAuthorization{
		nil,
		{},
	} {
		result, err := routeExplicitD1(
			context.Background(),
			authorization,
			request,
			composer,
		)
		if result != nil {
			t.Fatalf("writer refusal returned publication result %v", result)
		}
		var failure Failure
		if !errors.As(err, &failure) || failure.Code() != CodeUnsupported {
			t.Fatalf("writer refusal = %T %v; want closed unsupported code", err, err)
		}
	}

	if effects != (struct {
		stage, factor, entropy, source, destination int
	}{}) {
		t.Fatalf("writer refusal observed effects: %+v", effects)
	}
}
