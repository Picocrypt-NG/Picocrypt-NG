// Package pcv3 owns normal PCV3 format routing and structural admission.
package pcv3

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3governance"
	"context"
	"errors"
)

const normalDiscriminator = "PCV\x00"

var errInvalidD1Route = errors.New("pcv3: invalid D1 route")

type d1RouteMode uint8

const d1RouteExplicit d1RouteMode = iota + 1

type d1RouteRequest struct {
	mode            d1RouteMode
	sourcePath      string
	destinationPath string
}

type d1RouteComposer func(context.Context) error

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

func routeExplicitD1(
	ctx context.Context,
	authorization *pcv3governance.EmissionAuthorization,
	request *d1RouteRequest,
	compose d1RouteComposer,
) error {
	if ctx == nil || request == nil || request.mode != d1RouteExplicit ||
		request.sourcePath == "" || request.destinationPath == "" || compose == nil {
		return newError(OutcomeUnsupportedRoutingPreKDF, StageRouting, errInvalidD1Route)
	}

	sameFile, err := fileops.SamePathOrFile(request.sourcePath, request.destinationPath)
	if err != nil || sameFile {
		return newError(OutcomeUnsupportedRoutingPreKDF, StageRouting, errInvalidD1Route)
	}
	if err := pcv3governance.RequireEmissionAuthorization(authorization); err != nil {
		return newError(OutcomeUnsupportedRoutingPreKDF, StageRouting, err)
	}
	if err := ctx.Err(); err != nil {
		return newError(OutcomeOperationFailed, StageCancellation, err)
	}
	return compose(ctx)
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
