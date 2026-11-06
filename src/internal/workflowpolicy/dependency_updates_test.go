package workflowpolicy

import (
	"reflect"
	"slices"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestDependabotGroupsOnlyAndroidTestPatchVersionUpdates(t *testing.T) {
	var config struct {
		Updates []struct {
			Ecosystem string `yaml:"package-ecosystem"`
			Groups    map[string]struct {
				AppliesTo string   `yaml:"applies-to"`
				Patterns  []string `yaml:"patterns"`
				Types     []string `yaml:"update-types"`
			} `yaml:"groups"`
		} `yaml:"updates"`
	}
	if err := yaml.Unmarshal([]byte(mustReadRepoFile(t, ".github/dependabot.yml")), &config); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, update := range config.Updates {
		for name, group := range update.Groups {
			if update.Ecosystem != "gradle" || name != "android-test-patches" {
				t.Fatal("production and toolchain dependencies must retain individual review")
			}
			if group.AppliesTo != "version-updates" || !reflect.DeepEqual(group.Types, []string{"patch"}) {
				t.Fatal("test grouping must not combine security, minor or major updates")
			}
			want := []string{"androidx.arch.core:core-testing", "androidx.test.espresso:espresso-core", "androidx.test.ext:junit", "io.mockk:mockk", "junit:junit"}
			slices.Sort(group.Patterns)
			if !reflect.DeepEqual(group.Patterns, want) {
				t.Fatal("test grouping must use exact test-only coordinates, without production/BOM/compiler patterns")
			}
			found = true
		}
	}
	if !found {
		t.Fatal("missing Android test patch version-update group")
	}
}
