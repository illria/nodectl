package service

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCustom9StagingWorkflowBoundaries(t *testing.T) {
	source, err := os.ReadFile("../../.github/workflows/stage-custom9.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		On          map[string]any    `yaml:"on"`
		Env         map[string]string `yaml:"env"`
		Permissions map[string]string `yaml:"permissions"`
		Jobs        map[string]struct {
			If          string            `yaml:"if"`
			Needs       any               `yaml:"needs"`
			Env         map[string]string `yaml:"env"`
			Permissions map[string]string `yaml:"permissions"`
			Strategy    struct {
				Matrix struct {
					Goarch []string `yaml:"goarch"`
				} `yaml:"matrix"`
			} `yaml:"strategy"`
			Steps []struct {
				Uses string            `yaml:"uses"`
				Run  string            `yaml:"run"`
				Env  map[string]string `yaml:"env"`
				With map[string]any    `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(source, &workflow); err != nil {
		t.Fatalf("parse staging workflow: %v", err)
	}
	if _, ok := workflow.On["workflow_dispatch"]; !ok || len(workflow.On) != 1 {
		t.Fatalf("staging must only allow workflow_dispatch: %v", workflow.On)
	}
	for key, want := range map[string]string{
		"VERSION":       "v0.4.76-custom.9-rc",
		"AGENT_VERSION": "v0.2.78-rc",
		"STAGING_IMAGE": "ghcr.io/illria/nodectl:custom9-rc",
	} {
		if workflow.Env[key] != want {
			t.Errorf("staging %s = %q, want %q", key, workflow.Env[key], want)
		}
	}
	if len(workflow.Permissions) != 1 || workflow.Permissions["contents"] != "read" {
		t.Fatalf("staging default token permissions = %v", workflow.Permissions)
	}
	guard, ok := workflow.Jobs["validate-branch"]
	if !ok {
		t.Fatal("missing staging branch validation job")
	}
	var guardScript string
	for _, step := range guard.Steps {
		guardScript += step.Run
	}
	for _, required := range []string{"GITHUB_REF", "refs/heads/feat/server-side-relay-v9", "exit 1", "GITHUB_SHA", "VERSION", "AGENT_VERSION", "STAGING_IMAGE", "GITHUB_STEP_SUMMARY"} {
		if !strings.Contains(guardScript, required) {
			t.Errorf("branch validation must reject wrong refs: missing %q", required)
		}
	}
	uploads, dockerPushes, checkouts := 0, 0, 0
	for id, job := range workflow.Jobs {
		if _, override := job.Env["STAGING_IMAGE"]; override {
			t.Errorf("job %s must not override the staging-only Docker tag", id)
		}
		if id != "validate-branch" {
			if job.If != "github.ref == 'refs/heads/feat/server-side-relay-v9'" || !stageCustom9NeedsGuard(job.Needs) {
				t.Errorf("job %s must depend on the guard and require the feature branch", id)
			}
		}
		if id == "stage-image" {
			if len(job.Permissions) != 2 || job.Permissions["contents"] != "read" || job.Permissions["packages"] != "write" {
				t.Errorf("Docker job token permissions = %v", job.Permissions)
			}
		} else if len(job.Permissions) != 0 {
			t.Errorf("job %s must inherit read-only permissions", id)
		}
		if id == "build-panel" || id == "build-agent" {
			if strings.Join(job.Strategy.Matrix.Goarch, ",") != "amd64,arm64" {
				t.Errorf("job %s must build amd64 and arm64", id)
			}
		}
		for _, step := range job.Steps {
			if _, override := step.Env["STAGING_IMAGE"]; override {
				t.Errorf("job %s step must not override the staging-only Docker tag", id)
			}
			if strings.Contains(step.Uses, "release") || strings.Contains(step.Uses, "tag") {
				t.Errorf("staging contains a release/tag action: %s", step.Uses)
			}
			switch {
			case strings.HasPrefix(step.Uses, "actions/checkout@"):
				checkouts++
				if step.With["ref"] != "${{ github.sha }}" || fmt.Sprint(step.With["persist-credentials"]) != "false" {
					t.Errorf("job %s checkout must use immutable run HEAD without write credentials", id)
				}
			case strings.HasPrefix(step.Uses, "actions/upload-artifact@"):
				uploads++
				if step.Uses != "actions/upload-artifact@v4" || fmt.Sprint(step.With["retention-days"]) != "1" || step.With["if-no-files-found"] != "error" {
					t.Errorf("job %s artifact must use v4, 1-day retention, and reject absent binaries", id)
				}
				wantName := "nodectl-linux-${{ matrix.goarch }}"
				if id == "build-agent" {
					wantName = "nodectl-agent-linux-${{ matrix.goarch }}-${{ env.AGENT_VERSION }}"
				}
				if step.With["name"] != wantName || step.With["path"] != "bin/"+wantName {
					t.Errorf("job %s staging artifact name/path = %v", id, step.With)
				}
			case strings.HasPrefix(step.Uses, "docker/build-push-action@"):
				dockerPushes++
				if id != "stage-image" || step.With["tags"] != "${{ env.STAGING_IMAGE }}" || fmt.Sprint(step.With["push"]) != "true" || step.With["platforms"] != "linux/amd64,linux/arm64" {
					t.Errorf("staging Docker push must only publish the multiarch RC tag: %v", step.With)
				}
			}
			for _, forbidden := range []string{"action-gh-release", "gh release", "git tag", "push --tags", "refs/tags/"} {
				if strings.Contains(step.Uses+step.Run, forbidden) {
					t.Errorf("job %s contains forbidden release/tag operation %q", id, forbidden)
				}
			}
		}
	}
	if uploads != 2 || dockerPushes != 1 || checkouts != 3 {
		t.Errorf("staging needs both binary matrices and one Docker push from immutable checkouts: uploads=%d docker=%d checkouts=%d", uploads, dockerPushes, checkouts)
	}
}

func stageCustom9NeedsGuard(needs any) bool {
	if needs == "validate-branch" {
		return true
	}
	if jobs, ok := needs.([]any); ok {
		for _, job := range jobs {
			if job == "validate-branch" {
				return true
			}
		}
	}
	return false
}
