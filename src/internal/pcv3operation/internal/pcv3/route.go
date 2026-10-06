// Package pcv3 owns normal PCV3 format routing and structural admission.
package pcv3

const normalDiscriminator = "PCV\x00"

// Route identifies which format family may inspect an input.
type Route uint8

const (
	// RouteLegacyEligible leaves the input eligible for the frozen legacy path.
	RouteLegacyEligible Route = iota
	// RouteNormalPCV claims the normal PCV family without permitting fallback.
	RouteNormalPCV
)

// DetectPrefix claims the normal PCV family only for its complete discriminator.
func DetectPrefix(prefix []byte) Route {
	if len(prefix) < len(normalDiscriminator) {
		return RouteLegacyEligible
	}
	for index := range normalDiscriminator {
		if prefix[index] != normalDiscriminator[index] {
			return RouteLegacyEligible
		}
	}
	return RouteNormalPCV
}

// String returns a fixed, non-sensitive route name.
func (route Route) String() string {
	switch route {
	case RouteLegacyEligible:
		return "legacy-eligible"
	case RouteNormalPCV:
		return "normal-pcv"
	default:
		return "unknown-route"
	}
}
