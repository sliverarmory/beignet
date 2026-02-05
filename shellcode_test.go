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

	dylibPath := filepath.Join(tmp, "test.dylib")
	{
		cmd := exec.Command("go", "build", "-buildmode=c-shared", "-o", dylibPath, "./testdata/dylib")
		cmd.Env = append(os.Environ(),
			"GOCACHE="+filepath.Join(tmp, "go-build-cache"),
			"CGO_ENABLED=1",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("build dylib: %v\n%s", err, out)
		}
	}

	runnerPath := filepath.Join(tmp, "runner")
	{
		zigCache := filepath.Join(tmp, "zig-cache")
		if err := os.MkdirAll(zigCache, 0o755); err != nil {
			t.Fatalf("mkdir zig cache: %v", err)
		}
		cmd := exec.Command("zig", "cc", "-target", "aarch64-macos", "-o", runnerPath, "./testdata/runner/runner.c")
		cmd.Env = append(os.Environ(),
			"ZIG_GLOBAL_CACHE_DIR="+zigCache,
			"ZIG_LOCAL_CACHE_DIR="+zigCache,
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("build runner: %v\n%s", err, out)
		}
	}

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
