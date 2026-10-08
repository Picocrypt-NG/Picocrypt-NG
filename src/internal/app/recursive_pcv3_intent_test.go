package app

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRecursivePCV3IntentTransfersOnlyActiveNormalDecryptBatch(t *testing.T) {
	for _, test := range []struct {
		name                         string
		working, recursive, scanning bool
		format                       PCV3Format
		action                       PCV3Action
		want                         bool
	}{
		{"active Normal batch", true, true, false, PCV3FormatNormal, PCV3ActionDecrypt, true},
		{"not running", false, true, false, PCV3FormatNormal, PCV3ActionDecrypt, false},
		{"not recursive", true, false, false, PCV3FormatNormal, PCV3ActionDecrypt, false},
		{"scanning", true, true, true, PCV3FormatNormal, PCV3ActionDecrypt, false},
		{"D1 not implicit", true, true, false, PCV3FormatD1, PCV3ActionDecrypt, false},
		{"recovery not implicit", true, true, false, PCV3FormatNormal, PCV3ActionRecovery, false},
		{"Force not implicit", true, true, false, PCV3FormatNormal, PCV3ActionForce, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := mustNewState(t)
			path := filepath.Join(t.TempDir(), "source")
			body := []byte("held batch source")
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			source, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			if !state.SetPCV3Ready(source, test.format, path, path+".out", int64(len(body))) {
				t.Fatal("source not retained")
			}
			state.Password = "batch secret"
			state.Keyfiles = []string{"one", "two", "one"}
			state.SetPCV3Intent(test.action, PCV3FactorPolicyCombined, PCV3KeyfileOrderSelected)
			state.SetWorking(test.working)
			state.Recursively = test.recursive
			state.SetScanning(test.scanning)
			intent, ok := state.TakePCV3RecursiveOperationIntent()
			if ok != test.want {
				t.Fatalf("batch authority=%v want%v", ok, test.want)
			}
			if !ok {
				if intent.Source != nil || len(intent.Password) != 0 || len(intent.Keyfiles) != 0 {
					t.Fatal("rejected batch transferred resources")
				}
				state.ClosePCV3Source()
				return
			}
			defer clear(intent.Password)
			if intent.Source != source || string(intent.Password) != "batch secret" || !reflect.DeepEqual(intent.Keyfiles, []string{"one", "two", "one"}) {
				t.Fatal("batch lost exact descriptor or selected factors")
			}
			if state.Password != "" || len(state.Keyfiles) != 0 || !state.IsWorking() {
				t.Fatal("batch did not transfer credentials while keeping session active")
			}
			if _, ok := state.TakePCV3RecursiveOperationIntent(); ok {
				t.Fatal("batch transferred source twice")
			}
			state.ClosePCV3Source()
			got := make([]byte, len(body))
			if _, err := intent.Source.ReadAt(got, 0); err != nil || !bytes.Equal(got, body) {
				t.Fatalf("State still owned transferred source: %v", err)
			}
		})
	}
}

func TestRecursiveD1IntentRequiresExplicitBatchFormatAndCannotBeRetargeted(t *testing.T) {
	state := mustNewState(t)
	if state.SetRecursiveD1(true) {
		t.Fatal("D1 enabled without recursive selection")
	}
	state.Recursively = true
	state.SetScanning(true)
	if state.SetRecursiveD1(true) {
		t.Fatal("D1 selection changed during scan")
	}
	state.SetScanning(false)
	if !state.SetRecursiveD1(true) {
		t.Fatal("explicit D1 selection refused")
	}
	state.Mode = "encrypt"
	state.Password = "selected D1 password"
	state.CPassword = ""
	if !state.CanStart() || !state.UISnapshot().CanStart() {
		t.Fatal("explicit D1 required encryption confirmation")
	}
	saved := state.RecursiveSnapshot()
	if !saved.RecursiveD1 {
		t.Fatal("batch snapshot lost explicit D1 intent")
	}
	path := filepath.Join(t.TempDir(), "opaque")
	if err := os.WriteFile(path, []byte("held D1 source"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if !state.SetPCV3Ready(source, PCV3FormatD1, path, path+".out", 14) {
		t.Fatal("D1 source not held")
	}
	state.ApplyRecursiveSelection(saved)
	state.SetPCV3Intent(PCV3ActionDecrypt, PCV3FactorPolicyPassword, PCV3KeyfileOrderUnset)
	state.SetWorking(true)
	if state.SetRecursiveD1(false) || !state.RecursiveD1 {
		t.Fatal("running D1 batch was retargeted")
	}
	intent, ok := state.TakePCV3RecursiveOperationIntent()
	if !ok || intent.Format != PCV3FormatD1 || intent.Source != source {
		t.Fatalf("explicit D1 ownership transfer failed: %v", ok)
	}
	clear(intent.Password)
	state.SetWorking(false)
	state.ResetUI()
	if state.RecursiveD1 || state.UISnapshot().RecursiveD1 {
		t.Fatal("D1 batch intent survived selection reset")
	}
}
