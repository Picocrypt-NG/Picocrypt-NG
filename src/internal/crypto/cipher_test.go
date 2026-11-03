package crypto

import (
	"bytes"
	"reflect"
	"testing"
)

// Close must clear the complete expanded schedule, not just change the cipher's
// output by modifying some of its key material.
func TestCipherSuiteCloseWipesSerpentSchedule(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	nonce := bytes.Repeat([]byte{2}, 24)
	sKey := bytes.Repeat([]byte{3}, 32)
	sIV := bytes.Repeat([]byte{4}, 16)
	mac, err := NewMAC(bytes.Repeat([]byte{5}, 32), true)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := NewCipherSuite(key, nonce, sKey, sIV, mac, NewHKDFStream(key, nonce), true)
	if err != nil {
		t.Fatal(err)
	}
	schedule := reflect.ValueOf(cs.serpentS)
	if schedule.Kind() != reflect.Pointer || schedule.IsNil() {
		t.Fatal("Serpent block does not expose its retained schedule")
	}
	schedule = schedule.Elem()
	if schedule.Kind() != reflect.Array || schedule.Len() != 132 || schedule.Type().Elem().Kind() != reflect.Uint32 {
		t.Fatal("Serpent block no longer has the reviewed 132-word schedule")
	}
	if schedule.IsZero() {
		t.Fatal("initialized Serpent schedule is already zero")
	}

	cs.Close()

	for index := range schedule.Len() {
		if schedule.Index(index).Uint() != 0 {
			t.Fatalf("Serpent schedule word %d survived Close", index)
		}
	}
}
