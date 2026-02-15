package beignet_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sliverarmory/beignet"
)

const markerPath = "/tmp/beignet_test_marker"

func TestDylibToShellcode_Arm64Darwin(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("darwin/arm64 only")
	}

	tmp := t.TempDir()
	dylibPath := filepath.Join(tmp, "test-arm64.dylib")
	buildDylib(t, tmp, dylibPath, "arm64")

	runnerPath := filepath.Join(tmp, "runner-arm64")
	buildRunner(t, tmp, runnerPath, "aarch64-macos")

	runShellcodeCases(t, tmp, dylibPath, runnerPath, nil)
}

func TestDylibToShellcode_Amd64DarwinRosetta2(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("rosetta2 test requires darwin/arm64 host")
	}

	archPath := requireRosetta2(t)
	tmp := t.TempDir()

	bundlePath := filepath.Join(tmp, "test-amd64.bundle")
	buildMarkerBundleC(t, tmp, bundlePath)

	runnerPath := filepath.Join(tmp, "runner-amd64")
	buildRunner(t, tmp, runnerPath, "x86_64-macos")

	runShellcodeCases(t, tmp, bundlePath, runnerPath, []string{archPath, "-x86_64"})
}

func buildDylib(t *testing.T, tmp, dylibPath, goarch string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-buildmode=c-shared", "-o", dylibPath, "./testdata/dylib")
	env := append(os.Environ(),
		"GOCACHE="+filepath.Join(tmp, "go-build-cache-"+goarch),
		"CGO_ENABLED=1",
		"GOOS=darwin",
		"GOARCH="+goarch,
	)
	if goarch == "amd64" {
		env = append(env,
			"CC=zig cc -target x86_64-macos",
			"CXX=zig c++ -target x86_64-macos",
		)
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build %s dylib: %v\n%s", goarch, err, out)
	}
}

func buildRunner(t *testing.T, tmp, runnerPath, zigTarget string) {
	t.Helper()
	zigCache := filepath.Join(tmp, "zig-cache-"+zigTarget)
	if err := os.MkdirAll(zigCache, 0o755); err != nil {
		t.Fatalf("mkdir zig cache: %v", err)
	}
	cmd := exec.Command("zig", "cc", "-target", zigTarget, "-o", runnerPath, "./testdata/runner/runner.c")
	cmd.Env = append(os.Environ(),
		"ZIG_GLOBAL_CACHE_DIR="+zigCache,
		"ZIG_LOCAL_CACHE_DIR="+zigCache,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build runner (%s): %v\n%s", zigTarget, err, out)
	}
}

func buildMarkerBundleC(t *testing.T, tmp, bundlePath string) {
	t.Helper()
	src := filepath.Join(tmp, "marker_dylib.c")
	const markerDylibC = `
#include <fcntl.h>
#include <unistd.h>

__attribute__((visibility("default"))) void StartW(void) {
  const char* path = "/tmp/beignet_test_marker";
  int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
  if (fd >= 0) {
    (void)write(fd, "ok", 2);
    (void)close(fd);
  }
}
`
	if err := os.WriteFile(src, []byte(markerDylibC), 0o644); err != nil {
		t.Fatalf("write marker dylib source: %v", err)
	}

	// We intentionally build a Mach-O bundle here because dyld's
	// NSCreateObjectFileImageFromMemory path (used by the x86_64 loader to work
	// under Rosetta) only accepts MH_BUNDLE payloads.
	cmd := exec.Command("clang", "-target", "x86_64-apple-macos13", "-bundle", "-fPIC", "-o", bundlePath, src)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build marker bundle: %v\n%s", err, out)
	}
}

func requireRosetta2(t *testing.T) string {
	t.Helper()
	archPath, err := exec.LookPath("arch")
	if err != nil {
		t.Skipf("rosetta2 test requires arch utility: %v", err)
	}
	cmd := exec.Command(archPath, "-x86_64", "/usr/bin/true")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("rosetta2 not available: %v\n%s", err, out)
	}
	return archPath
}

func runShellcodeCases(t *testing.T, tmp, dylibPath, runnerPath string, runnerPrefix []string) {
	t.Helper()
	cases := []struct {
		name string
		opts beignet.Options
	}{
		{
			name: "raw",
			opts: beignet.Options{EntrySymbol: "_StartW"},
		},
		{
			name: "aplib",
			opts: beignet.Options{EntrySymbol: "_StartW", Compress: true},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc, err := beignet.DylibFileToShellcode(dylibPath, tc.opts)
			if err != nil {
				t.Fatalf("DylibFileToShellcode: %v", err)
			}

			shellcodePath := filepath.Join(tmp, "shellcode-"+tc.name+".bin")
			if err := os.WriteFile(shellcodePath, sc, 0o644); err != nil {
				t.Fatalf("write shellcode: %v", err)
			}

			_ = os.Remove(markerPath)

			cmd := exec.Command(runnerPath, shellcodePath)
			if len(runnerPrefix) > 0 {
				args := append([]string{}, runnerPrefix...)
				args = append(args, runnerPath, shellcodePath)
				cmd = exec.Command(args[0], args[1:]...)
			}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("runner failed: %v\n%s", err, out)
			}

			got, err := os.ReadFile(markerPath)
			if err != nil {
				t.Fatalf("marker not written: %v", err)
			}
			if !bytes.Equal(bytes.TrimSpace(got), []byte("ok")) {
				t.Fatalf("unexpected marker contents: %q", got)
			}
		})
	}
}
