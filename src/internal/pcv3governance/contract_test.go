package pcv3governance

import (
	"errors"
	"reflect"
	"testing"
)

func TestEmissionAuthorizationRequiresFinalPromotionPredicate(t *testing.T) {
	zero := &EmissionAuthorization{}
	if err := RequireEmissionAuthorization(zero); err == nil {
		t.Fatal("zero-value EmissionAuthorization was accepted")
	} else {
		var refusal *RefusalError
		if !errors.As(err, &refusal) || refusal.Reason != ReasonAuthorizationMissing {
			t.Fatalf("zero-value authorization error = %v, want typed missing-authorization refusal", err)
		}
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
