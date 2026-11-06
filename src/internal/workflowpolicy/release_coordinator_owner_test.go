package workflowpolicy

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestReleaseCoordinatorModesAndRealOwnerCalls(t *testing.T) {
	content := mustReadWorkflow(t, ".github/workflows/release.yml")
	var document struct {
		On struct {
			Dispatch struct {
				Inputs map[string]struct {
					Default string
					Options []string
				}
			} `yaml:"workflow_dispatch"`
		} `yaml:"on"`
		Concurrency workflowConcurrency
		Jobs        map[string]struct{ Secrets map[string]string }
	}
	if err := yaml.Unmarshal([]byte(content), &document); err != nil {
		t.Fatal(err)
	}
	mode := document.On.Dispatch.Inputs["mode"]
	if mode.Default != "validation" || !reflect.DeepEqual(mode.Options, []string{"validation", "stage", "publish"}) {
		t.Fatal("coordinator must default to validation and expose separately authorized stage/publish")
	}
	if document.Concurrency.Group == "${{ github.repository }}-release-publication" || document.Concurrency.CancelInProgress != false {
		t.Fatal("parent workflow must not hold the callee publication lock or cancel retained work")
	}
	workflow := mustReadWorkflowDoc(t, ".github/workflows/release.yml")
	for _, owner := range []string{"linux", "macos", "snapcraft", "android", "windows", "windows-legacy", "appimage"} {
		t.Run(owner, func(t *testing.T) {
			job := mustJob(t, workflow, "owner-"+owner)
			if job.Uses != "./.github/workflows/build-"+owner+".yml" {
				t.Fatal("publication must call the real owner at the same commit")
			}
			for _, condition := range []string{"!cancelled()", "inputs.mode != 'validation'", "needs.validation.result == 'success'"} {
				mustContain(t, job.If, condition)
			}
			if !strings.Contains(fmt.Sprint(job.Needs), "prepare") || !strings.Contains(fmt.Sprint(job.Needs), "validation") {
				t.Fatal("owner must wait for prepared source and the complete19 barrier")
			}
			if !reflect.DeepEqual(job.Permissions, map[string]string{"contents": "write", "actions": "read", "id-token": "write", "attestations": "write"}) {
				t.Fatal("only owner calls receive the exact required permission ceiling")
			}
			for input, output := range map[string]string{"source_sha": "source-sha", "version": "version", "canonical_manifest_sha256": "manifest-digest"} {
				if job.Steps != nil || job.Environment != nil || job.Outputs != nil {
					t.Fatal("caller must not duplicate owner steps, environments or outputs")
				}
				var with struct {
					Jobs map[string]struct{ With map[string]string }
				}
				if err := yaml.Unmarshal([]byte(content), &with); err != nil {
					t.Fatal(err)
				}
				if with.Jobs["owner-"+owner].With[input] != "${{ needs.prepare.outputs."+output+" }}" {
					t.Fatal("owner source input is not prepared")
				}
			}
			wantSecrets := map[string]string{}
			switch owner {
			case "android":
				for _, name := range []string{"ANDROID_KEYSTORE_BASE64", "ANDROID_KEYSTORE_PASSWORD", "ANDROID_KEY_ALIAS", "ANDROID_KEY_PASSWORD"} {
					wantSecrets[name] = "${{ secrets." + name + " }}"
				}
			case "windows", "windows-legacy":
				wantSecrets["SIGNPATH_API_TOKEN"] = "${{ secrets.SIGNPATH_API_TOKEN }}"
			case "appimage":
				for _, name := range []string{"APPIMAGE_GPG_PRIVATE_KEY", "APPIMAGE_GPG_PASSPHRASE"} {
					wantSecrets[name] = "${{ secrets." + name + " }}"
				}
			}
			got := document.Jobs["owner-"+owner].Secrets
			if len(got) != len(wantSecrets) {
				t.Fatal("secrets must be explicit names, never inherited or broadened")
			}
			for key, value := range wantSecrets {
				if got[key] != value {
					t.Fatalf("missing exact secret name mapping %s", key)
				}
			}
		})
	}
}

func TestReleaseCoordinatorUsesRealRawAndSigningCarriers(t *testing.T) {
	var document struct {
		Jobs map[string]struct {
			Outputs map[string]string
			With    map[string]string
			Steps   []workflowStep
		}
	}
	if err := yaml.Unmarshal([]byte(mustReadWorkflow(t, ".github/workflows/release.yml")), &document); err != nil {
		t.Fatal(err)
	}
	for _, owner := range []string{"macos", "snapcraft", "android", "windows", "windows-legacy", "appimage"} {
		call := document.Jobs["owner-"+owner].With
		for input, output := range map[string]string{"raw_artifact_id": "artifact-id", "raw_artifact_digest": "artifact-digest", "raw_producing_attempt": "run-attempt"} {
			if call[input] != "${{ needs.build-"+owner+".outputs."+output+" }}" {
				t.Fatal("single-owner raw input must retain the real canonical carrier tuple")
			}
		}
		if owner == "android" || owner == "windows" || owner == "windows-legacy" || owner == "appimage" {
			for input, output := range map[string]string{"signing_input_id": "signing-input-id", "signing_input_digest": "signing-input-digest", "signing_input_attempt": "signing-input-attempt"} {
				if call[input] != "${{ needs.build-"+owner+".outputs."+output+" }}" || document.Jobs["build-"+owner].Outputs[output] != "${{ steps.build.outputs."+output+" }}" {
					t.Fatal("native carrier outputs must forward the actual original signing input, not an alias")
				}
			}
		}
	}
	for _, arch := range []string{"amd64", "arm64"} {
		for input, output := range map[string]string{"artifact_id": "artifact-id", "artifact_digest": "artifact-digest", "producing_attempt": "run-attempt"} {
			if document.Jobs["owner-linux"].With[arch+"_"+input] != "${{ needs.build-"+arch+".outputs."+output+" }}" {
				t.Fatal("Linux must retain both independent raw carrier tuples")
			}
		}
	}
	if document.Jobs["owner-appimage"].With["signing_input_sha256"] != "${{ needs.build-appimage.outputs.signing-input-sha256 }}" || document.Jobs["build-appimage"].Outputs["signing-input-sha256"] != "${{ steps.build.outputs.signing-input-sha256 }}" {
		t.Fatal("AppDir tar SHA must remain separate from official ZIP digest")
	}
	call := mustHaveStepUsingPrefix(t, mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/release.yml"), "build-appimage"), "./.github/actions/build-appimage")
	if call.With["retain-signing-input"] != "${{ inputs.mode != 'validation' }}" {
		t.Fatal("AppImage must retain the existing native AppDir once, only for requested stage/publish")
	}
}

func TestReleaseCoordinatorFinalizeNeedsAllOwnersAndTruthfulOutput(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/release.yml")
	job := mustJob(t, workflow, "publish")
	for _, condition := range []string{"always()", "!cancelled()", "inputs.mode == 'publish'"} {
		mustContain(t, job.If, condition)
	}
	if job.Environment != "release" || !reflect.DeepEqual(job.Permissions, map[string]string{"contents": "write", "actions": "read"}) {
		t.Fatal("finalization must have no OIDC/attestation authority")
	}
	if len(job.Steps) == 0 || job.Steps[0].Name != "Require every staged owner" {
		t.Fatal("every owner result/staged flag must be checked before any API write")
	}
	for _, owner := range []string{"linux", "macos", "snapcraft", "android", "windows", "windows-legacy", "appimage"} {
		if !strings.Contains(fmt.Sprint(job.Needs), "owner-"+owner) {
			t.Fatal("finalization is missing an actual owner dependency")
		}
	}
	step := mustStepNamed(t, job, "Strictly finalize complete release")
	if step.ID != "finalize" || step.Run != "bash .github/actions/stage-release/release-gate.sh strict-finalize \"$SOURCE_VERSION\"" || step.Env["GH_TOKEN"] != "${{ github.token }}" {
		t.Fatal("publish must use strict actual publication, never legacy partial-success mode")
	}
	confirm := mustStepNamed(t, job, "Require confirmed publication")
	if confirm.Env["PUBLISHED"] != "${{ steps.finalize.outputs.published }}" || !strings.Contains(confirm.Run, `test "$PUBLISHED" = true`) {
		t.Fatal("publication cannot succeed without the actual published=true output")
	}
	if job.Outputs["published"] != "${{ steps.finalize.outputs.published }}" {
		t.Fatal("summary must consume the real finalizer result")
	}
	result := mustJob(t, workflow, "result")
	if result.Environment != nil || result.Permissions["contents"] != "read" {
		t.Fatal("outcome reporting must remain readonly")
	}
	mustStepNamed(t, result, "Summarize and require requested outcome")
}

func TestReleaseCoordinatorFinalizerSharesOwnerPublicationQueue(t *testing.T) {
	job := mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/release.yml"), "publish")
	if job.Concurrency.Group != "${{ github.repository }}-release-publication" || job.Concurrency.Queue != "max" || job.Concurrency.CancelInProgress != nil {
		t.Fatal("final publication must serialize with owner staging and direct dispatches in the shared non-cancelling queue")
	}
}

func TestReleaseCoordinatorCallsMatchDeclaredOwnerSchemas(t *testing.T) {
	var coordinator struct {
		Jobs map[string]struct {
			Uses    string
			With    map[string]string
			Secrets map[string]string
		}
	}
	if err := yaml.Unmarshal([]byte(mustReadWorkflow(t, ".github/workflows/release.yml")), &coordinator); err != nil {
		t.Fatal(err)
	}
	for _, owner := range []string{"linux", "macos", "snapcraft", "android", "windows", "windows-legacy", "appimage"} {
		t.Run(owner, func(t *testing.T) {
			call := coordinator.Jobs["owner-"+owner]
			var callee struct {
				On struct {
					Call struct {
						Inputs map[string]struct {
							Required bool
							Type     string
						}
						Secrets map[string]struct{ Required bool }
						Outputs map[string]struct{ Value string }
					} `yaml:"workflow_call"`
				} `yaml:"on"`
			}
			if err := yaml.Unmarshal([]byte(mustReadWorkflow(t, strings.TrimPrefix(call.Uses, "./"))), &callee); err != nil {
				t.Fatal(err)
			}
			if len(call.With) != len(callee.On.Call.Inputs) || len(call.Secrets) != len(callee.On.Call.Secrets) {
				t.Fatal("caller must match the actual owner schema without dummy or omitted inputs/secrets")
			}
			for key, input := range callee.On.Call.Inputs {
				if !input.Required || input.Type != "string" || call.With[key] == "" {
					t.Fatalf("owner input %s must bind the real required string", key)
				}
			}
			for key, secret := range callee.On.Call.Secrets {
				if !secret.Required || call.Secrets[key] != "${{ secrets."+key+" }}" {
					t.Fatalf("owner secret %s must be declared and explicitly mapped", key)
				}
			}
			for _, key := range []string{"staged", "reused", "generation_id", "generation_digest", "generation_attempt"} {
				if callee.On.Call.Outputs[key].Value == "" {
					t.Fatalf("owner must expose actual %s", key)
				}
			}
		})
	}
}
