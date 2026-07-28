package pcv3governance

import (
	"errors"
	"reflect"
	"testing"
)

func TestEmissionAuthorizationRequiresFinalPromotionPredicate(t *testing.T) {
	for _, test := range []struct {
		name          string
		authorization *EmissionAuthorization
	}{
		{name: "nil", authorization: nil},
		{name: "zero value", authorization: &EmissionAuthorization{}},
		{
			name:          "counterfeit marker with matching contents",
			authorization: &EmissionAuthorization{marker: &emissionMarker{nonzero: 1}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := RequireEmissionAuthorization(test.authorization)
			var refusal *RefusalError
			if !errors.As(err, &refusal) {
				t.Fatalf("RequireEmissionAuthorization error = %v, want typed missing-authorization refusal", err)
			}
			if refusal.Reason != ReasonAuthorizationMissing || refusal.Field != "" {
				t.Fatalf(
					"RequireEmissionAuthorization refusal = %s/%s, want %s with no field",
					refusal.Reason,
					refusal.Field,
					ReasonAuthorizationMissing,
				)
			}
		})
	}

	authorization, err := validatePromotionAgainst(finalBaseline(t), completePromotion(t))
	if err != nil {
		t.Fatalf("future final predicate with complete synthetic record: %v", err)
	}
	if authorization == nil {
		t.Fatal("validated synthetic record returned nil authorization")
	}
	if err := RequireEmissionAuthorization(authorization); err != nil {
		t.Fatalf("validated authorization rejected at future writer seam: %v", err)
	}
	if got := WriterStatus(); got != WriterDisabled {
		t.Fatalf("WriterStatus() after validated promotion = %v, want WriterDisabled", got)
	}
}

func TestEmissionAuthorizationHasNoPublicActivationState(t *testing.T) {
	typ := reflect.TypeFor[EmissionAuthorization]()
	if typ.NumMethod() != 0 {
		t.Fatalf("EmissionAuthorization has %d public methods; it must not expose an activation setter", typ.NumMethod())
	}
	for index := range typ.NumField() {
		field := typ.Field(index)
		if field.PkgPath == "" {
			t.Fatalf("EmissionAuthorization exposes field %q; zero construction must not activate writer emission", field.Name)
		}
	}
}
