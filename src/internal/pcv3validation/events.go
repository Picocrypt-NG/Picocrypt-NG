package pcv3validation

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// TestEvent is one allowlisted line of `go test -json` output. Only the
// fields the campaign reasons about are retained; raw streams are transient
// and never enter retained evidence.
type TestEvent struct {
	Action  string `json:"Action"`
	Package string `json:"Package"`
	Test    string `json:"Test"`
	Output  string `json:"Output"`
}

// allowedEventActions is the closed set of go test event actions the campaign
// accepts. Anything else (bench, pause, cont, start, ...) invalidates the
// stream.
var allowedEventActions = map[string]bool{
	"run":    true,
	"pass":   true,
	"fail":   true,
	"skip":   true,
	"output": true,
}

// OracleSelector identifies exactly one product oracle: the event package
// (module path + package directory), the top-level test, and the required
// subtest when the manifest freezes one ("" otherwise).
type OracleSelector struct {
	EventPackage string
	Test         string
	Subtest      string
}

func (selector OracleSelector) subtestPath() string {
	return selector.Test + "/" + selector.Subtest
}

// Rejection is a closed classification of why an event stream, transform, or
// outcome cannot count. Detail is diagnostic text; Kind is the machine
// classification.
type Rejection struct {
	Kind   Classification
	Detail string
}

func (rejection *Rejection) Error() string {
	return fmt.Sprintf("%s: %s", rejection.Kind, rejection.Detail)
}

// EventInventory counts the allowlisted events inside one named test tree.
type EventInventory struct {
	Runs          int // run events with Test == selector.Test
	Passes        int // pass events with Test == selector.Test
	Fails         int // fail events with Test == selector.Test
	TreeSkips     int // skip events anywhere in the named test tree
	SubtestRuns   int // run events for the exact required subtest
	SubtestPasses int // pass events for the exact required subtest
	SubtestFails  int // fail events for the exact required subtest
}

// ParseTestEvents decodes a `go test -json` stream. Every non-empty line must
// be a JSON event with an allowlisted action; anything else is rejected.
func ParseTestEvents(data []byte) ([]TestEvent, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var events []TestEvent
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var event TestEvent
		if err := json.Unmarshal(line, &event); err != nil {
			return nil, fmt.Errorf("decode go test event: %w", err)
		}
		if !allowedEventActions[event.Action] {
			return nil, fmt.Errorf("go test event action %q is not allowlisted", event.Action)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan go test events: %w", err)
	}
	return events, nil
}

// NewEventInventory validates the stream envelope and counts the named test
// tree. Every event must belong to the selected package, and no test outside
// the named tree may appear at all.
func NewEventInventory(events []TestEvent, selector OracleSelector) (EventInventory, *Rejection) {
	if selector.EventPackage == "" || selector.Test == "" {
		return EventInventory{}, &Rejection{Kind: ClassEventInvalid, Detail: "empty oracle selector"}
	}
	if selector.Subtest != "" && strings.ContainsAny(selector.Subtest, "\r\n") {
		return EventInventory{}, &Rejection{Kind: ClassEventInvalid, Detail: "invalid required subtest"}
	}
	var inventory EventInventory
	for _, event := range events {
		if event.Package != selector.EventPackage {
			return EventInventory{}, &Rejection{
				Kind:   ClassUnexpectedTest,
				Detail: "event stream contains a foreign package",
			}
		}
		if event.Test == "" {
			continue
		}
		inTree := event.Test == selector.Test || strings.HasPrefix(event.Test, selector.Test+"/")
		if !inTree {
			return EventInventory{}, &Rejection{
				Kind:   ClassUnexpectedTest,
				Detail: "event stream contains an unexpected test",
			}
		}
		if event.Action == "skip" {
			inventory.TreeSkips++
		}
		switch event.Test {
		case selector.Test:
			switch event.Action {
			case "run":
				inventory.Runs++
			case "pass":
				inventory.Passes++
			case "fail":
				inventory.Fails++
			}
		case selector.subtestPath():
			if selector.Subtest == "" {
				continue
			}
			switch event.Action {
			case "run":
				inventory.SubtestRuns++
			case "pass":
				inventory.SubtestPasses++
			case "fail":
				inventory.SubtestFails++
			}
		}
	}
	return inventory, nil
}

// AcceptPristine requires the pristine oracle to have run and passed exactly
// once with no skip, no failure, and no unexpected test.
func AcceptPristine(events []TestEvent, selector OracleSelector) (EventInventory, *Rejection) {
	inventory, rejection := NewEventInventory(events, selector)
	if rejection != nil {
		return inventory, rejection
	}
	if inventory.TreeSkips != 0 {
		return inventory, &Rejection{Kind: ClassRequiredSkip, Detail: "pristine oracle skipped"}
	}
	if inventory.Runs == 0 {
		return inventory, &Rejection{Kind: ClassPristineMissing, Detail: "pristine oracle never ran (missing pristine event)"}
	}
	if inventory.Runs != 1 || inventory.Passes > 1 {
		return inventory, &Rejection{Kind: ClassEventInvalid, Detail: "duplicate pristine run/pass events"}
	}
	if inventory.Fails != 0 || inventory.SubtestFails != 0 || inventory.Passes != 1 {
		return inventory, &Rejection{Kind: ClassPristineFailed, Detail: "pristine oracle did not pass exactly once"}
	}
	if selector.Subtest != "" {
		if inventory.SubtestRuns == 0 {
			return inventory, &Rejection{Kind: ClassPristineMissing, Detail: "required pristine subtest never ran"}
		}
		if inventory.SubtestRuns != 1 || inventory.SubtestPasses != 1 {
			return inventory, &Rejection{Kind: ClassPristineFailed, Detail: "required pristine subtest did not pass exactly once"}
		}
	}
	return inventory, nil
}

// AcceptMutant requires the mutant oracle to have failed exactly once for the
// frozen behavioral marker. A pass (survived), a skip, a missing selector, a
// process failure without the named failure (unrelated), or a failure without
// the frozen marker (error-only) is never a kill. processFailed reports the
// non-zero exit of the go test process.
func AcceptMutant(events []TestEvent, selector OracleSelector, marker string, processFailed bool) (EventInventory, *Rejection) {
	inventory, rejection := NewEventInventory(events, selector)
	if rejection != nil {
		return inventory, rejection
	}
	if marker == "" {
		return inventory, &Rejection{Kind: ClassEventInvalid, Detail: "empty frozen behavioral marker"}
	}
	if inventory.TreeSkips != 0 {
		return inventory, &Rejection{Kind: ClassRequiredSkip, Detail: "mutant oracle skipped"}
	}
	if inventory.Runs == 0 {
		return inventory, &Rejection{Kind: ClassSelectorMissing, Detail: "mutant oracle never ran (missing selector)"}
	}
	if inventory.Runs != 1 {
		return inventory, &Rejection{Kind: ClassEventInvalid, Detail: "duplicate mutant run events"}
	}
	if inventory.Passes != 0 {
		return inventory, &Rejection{Kind: ClassSurvived, Detail: "mutant oracle passed"}
	}
	if inventory.Fails == 0 {
		if processFailed {
			return inventory, &Rejection{Kind: ClassUnrelatedFailure, Detail: "test process failed without the named oracle failing"}
		}
		return inventory, &Rejection{Kind: ClassEventInvalid, Detail: "mutant oracle has no terminal event"}
	}
	if inventory.Fails != 1 {
		return inventory, &Rejection{Kind: ClassEventInvalid, Detail: "duplicate mutant fail events"}
	}
	if selector.Subtest != "" {
		if inventory.SubtestRuns == 0 {
			return inventory, &Rejection{Kind: ClassSelectorMissing, Detail: "required mutant subtest never ran"}
		}
		if inventory.SubtestFails != 1 {
			return inventory, &Rejection{Kind: ClassUnrelatedFailure, Detail: "the named oracle failed outside its required subtest"}
		}
		for _, event := range events {
			if event.Action == "output" && event.Test == selector.subtestPath() &&
				strings.Contains(event.Output, marker) {
				return inventory, nil
			}
		}
		return inventory, &Rejection{Kind: ClassMarkerMissing, Detail: "named failure lacks the frozen behavioral marker (error-only is not a kill)"}
	}
	for _, event := range events {
		inTree := event.Test == selector.Test || strings.HasPrefix(event.Test, selector.Test+"/")
		if event.Action == "output" && inTree && strings.Contains(event.Output, marker) {
			return inventory, nil
		}
	}
	return inventory, &Rejection{Kind: ClassMarkerMissing, Detail: "named failure lacks the frozen behavioral marker (error-only is not a kill)"}
}
