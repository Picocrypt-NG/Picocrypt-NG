package ui

import "testing"

func TestSettingsMenuRememberWindowSettingsToggleIndependently(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	owner := &App{fyneApp: fyneApp}
	selector := &settingsSelector{owner: owner}

	if owner.rememberWindowPositionEnabled() {
		t.Fatal("Remember window position should be disabled by default")
	}
	if owner.rememberWindowSizeEnabled() {
		t.Fatal("Remember window size should be disabled by default")
	}

	menu := selector.menu()
	if len(menu.Items) != 2 {
		t.Fatalf("Settings menu contains %d items; want 2", len(menu.Items))
	}
	if menu.Items[0].Checked || menu.Items[1].Checked {
		t.Fatal("Both window settings should be unchecked by default")
	}

	menu.Items[0].Action()
	if !owner.rememberWindowPositionEnabled() || owner.rememberWindowSizeEnabled() {
		t.Fatal("Enabling window position should not change the window size setting")
	}

	fyneApp.Preferences().SetBool(windowPositionSavedPreferenceKey, true)
	fyneApp.Preferences().SetBool(windowSizeSavedPreferenceKey, true)
	menu = selector.menu()
	menu.Items[1].Action()
	if !owner.rememberWindowPositionEnabled() || !owner.rememberWindowSizeEnabled() {
		t.Fatal("Window position and size settings should be independently enabled")
	}

	menu = selector.menu()
	if !menu.Items[0].Checked || !menu.Items[1].Checked {
		t.Fatal("Enabled window settings should be checked")
	}

	menu.Items[0].Action()
	if owner.rememberWindowPositionEnabled() {
		t.Fatal("Remember window position was not disabled")
	}
	if fyneApp.Preferences().BoolWithFallback(windowPositionSavedPreferenceKey, true) {
		t.Fatal("Disabling position remembering should invalidate only the saved position")
	}
	if !owner.rememberWindowSizeEnabled() {
		t.Fatal("Disabling position remembering must not disable size remembering")
	}
	if !fyneApp.Preferences().BoolWithFallback(windowSizeSavedPreferenceKey, false) {
		t.Fatal("Disabling position remembering must preserve the saved size")
	}

	menu = selector.menu()
	menu.Items[1].Action()
	if owner.rememberWindowSizeEnabled() {
		t.Fatal("Remember window size was not disabled")
	}
	if fyneApp.Preferences().BoolWithFallback(windowSizeSavedPreferenceKey, true) {
		t.Fatal("Disabling size remembering should invalidate the saved size")
	}
}
