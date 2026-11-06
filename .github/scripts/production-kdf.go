package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
)

type processStats struct {
	Arguments      []string `json:"arguments"`
	ElapsedSeconds float64  `json:"elapsed_seconds"`
	MaxRSSKiB      int64    `json:"max_child_rss_kib"`
	ExitCode       int      `json:"exit_code"`
	Error          string   `json:"error,omitempty"`
}

type runner struct {
	Dir      string
	Output   string
	Commands []processStats
}

type laneReport struct {
	Status            string            `json:"status"`
	Error             string            `json:"error,omitempty"`
	StartedAt         time.Time         `json:"started_at"`
	FinishedAt        time.Time         `json:"finished_at,omitempty"`
	ElapsedSeconds    float64           `json:"elapsed_seconds"`
	SourceSHA         string            `json:"source_sha"`
	Dirty             bool              `json:"dirty"`
	GoVersion         string            `json:"go_version"`
	GoEnvironment     map[string]string `json:"go_environment"`
	LimitsProvisional bool              `json:"limits_provisional"`
	PackageTimeout    string            `json:"package_timeout"`
	LaneTimeout       string            `json:"lane_timeout"`
	MemoryBefore      map[string]string `json:"memory_before"`
	MemoryAfter       map[string]string `json:"memory_after"`
	Discovery         discovery         `json:"discovery"`
	Commands          []processStats    `json:"commands"`
}

// Initial budgets from a 15-minute pilot capped at two CPUs and 4 GiB.
// Keep them provisional until the complete lane has been measured in hosted CI.
const (
	packageTimeout = "30m"
	laneTimeout    = 60 * time.Minute
)

func validateEnvironment(arguments []string) error {
	if len(arguments) != 0 {
		return errors.New("production-KDF runner accepts no arguments or test selectors")
	}
	if os.Getenv("GOFLAGS") != "" {
		return errors.New("unset GOFLAGS before running the complete production-KDF lane")
	}
	for _, entry := range os.Environ() {
		name, value, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(name, "PICOCRYPT_") || value == "" {
			continue
		}
		switch name {
		case "PICOCRYPT_RUN_CLI_INTEGRATION", "PICOCRYPT_RUN_RECOVERY_LARGE", "PICOCRYPT_PRODUCTION_KDF_REPORT_DIR":
		default:
			return fmt.Errorf("unset unsupported parent environment control %s before the complete production-KDF lane", name)
		}
	}
	if value := os.Getenv("PICOCRYPT_RUN_RECOVERY_LARGE"); value != "" && value != "1" {
		return errors.New("PICOCRYPT_RUN_RECOVERY_LARGE must be unset or 1")
	}
	return nil
}

func (r *runner) save(report *laneReport) error {
	report.Commands = r.Commands
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(r.Output, "report.json")
	if err := os.WriteFile(path+".tmp", append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

func (r *runner) run(ctx context.Context, report *laneReport) error {
	report.Status = "incomplete"
	report.LimitsProvisional = true
	report.PackageTimeout, report.LaneTimeout = packageTimeout, laneTimeout.String()
	if report.StartedAt.IsZero() {
		report.StartedAt = time.Now().UTC()
	}
	if err := r.save(report); err != nil {
		return err
	}
	err := r.execute(ctx, report)
	err = errors.Join(err, ctx.Err())
	report.FinishedAt = time.Now().UTC()
	report.ElapsedSeconds = report.FinishedAt.Sub(report.StartedAt).Seconds()
	report.MemoryAfter = memorySnapshot()
	report.Status = "passed"
	if err != nil {
		report.Status, report.Error = "failed", err.Error()
	}
	return errors.Join(err, r.save(report))
}

func (r *runner) execute(ctx context.Context, report *laneReport) error {
	if err := validateEnvironment(nil); err != nil {
		return err
	}
	discovered, err := r.discover(ctx)
	report.Discovery = discovered
	if err != nil {
		return err
	}
	if err := r.save(report); err != nil {
		return err
	}
	fmt.Printf("Discovered %d packages, %d parents, %d production-tag parents\n", len(discovered.Packages), len(discovered.Parents), len(discovered.Production))
	data, err := r.logged(ctx, "execution.jsonl", "go", "test", "-json", "-count=1", "-p", "1", "-parallel", "1",
		"-tags", "migrated_fynedo,pcv3_production_kdf", "-timeout", packageTimeout,
		"./internal/pcv3operation/...", "./internal/cli")
	if err != nil {
		return err
	}
	return verifyExecution(bytes.NewReader(data), discovered, os.Getenv("PICOCRYPT_RUN_RECOVERY_LARGE") != "1")
}

func memorySnapshot() map[string]string {
	facts := make(map[string]string)
	if runtime.GOOS != "linux" {
		facts["availability"] = "Linux procfs/cgroup facts unavailable on " + runtime.GOOS
		return facts
	}
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "MemAvailable:") {
				facts["/proc/meminfo/MemAvailable"] = strings.TrimSpace(strings.TrimPrefix(line, "MemAvailable:"))
			}
		}
	}
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		facts["/proc/self/cgroup"] = err.Error()
		return facts
	}
	facts["/proc/self/cgroup"] = strings.TrimSpace(string(data))
	root, err := os.OpenRoot("/sys/fs/cgroup")
	if err != nil {
		facts["cgroup_availability"] = err.Error()
		return facts
	}
	defer func() {
		if err := root.Close(); err != nil {
			facts["cgroup_close_error"] = err.Error()
		}
	}()
	readControls := false
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "0::/") {
			continue
		}
		membership := strings.TrimPrefix(line, "0::")
		if filepath.Clean(membership) != membership {
			facts["cgroup"] = "non-canonical membership; inspect /proc/self/cgroup"
			break
		}
		for path := filepath.Clean(strings.TrimPrefix(membership, "/")); ; path = filepath.Dir(path) {
			for _, name := range []string{"memory.max", "memory.high", "memory.current", "memory.peak", "memory.events", "memory.swap.max"} {
				file := filepath.Join(path, name)
				if value, err := root.ReadFile(file); err == nil {
					facts[filepath.Join("/sys/fs/cgroup", file)] = strings.TrimSpace(string(value))
					readControls = true
				}
			}
			if path == "." {
				break
			}
		}
	}
	if !readControls {
		facts["cgroup_availability"] = "no readable cgroup v2 memory controls under /sys/fs/cgroup"
	}
	return facts
}

func runProcess(ctx context.Context, dir string, arguments []string, stdout, stderr io.Writer) (processStats, error) {
	stats := processStats{Arguments: arguments, ExitCode: -1}
	started := time.Now()
	cmd := exec.CommandContext(ctx, arguments[0], arguments[1:]...)
	cmd.Dir, cmd.Stdout, cmd.Stderr = dir, stdout, stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	var cleanupErr error
	if cmd.Process != nil {
		cleanupErr = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		switch {
		case cleanupErr == nil:
			cleanupErr = errors.New("terminated residual owned process group after driver exit")
		case errors.Is(cleanupErr, syscall.ESRCH):
			cleanupErr = nil
		default:
			cleanupErr = fmt.Errorf("terminate residual owned process group after driver exit: %w", cleanupErr)
		}
	}
	stats.ElapsedSeconds = time.Since(started).Seconds()
	if cmd.ProcessState != nil {
		stats.ExitCode = cmd.ProcessState.ExitCode()
		if usage, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage); ok {
			// wait4's maximum child RSS is not simultaneous process-tree RSS.
			stats.MaxRSSKiB = usage.Maxrss
			if runtime.GOOS == "darwin" {
				stats.MaxRSSKiB /= 1024
			}
		}
	}
	err = errors.Join(err, ctx.Err(), cleanupErr)
	if err != nil {
		stats.Error = err.Error()
	}
	return stats, err
}

func (r *runner) logged(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	stdout, err := os.OpenFile(filepath.Join(r.Output, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	stderr, err := os.OpenFile(filepath.Join(r.Output, name+".stderr.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, errors.Join(err, stdout.Close())
	}
	stats, runErr := runProcess(ctx, r.Dir, arguments, stdout, stderr)
	r.Commands = append(r.Commands, stats)
	if err := errors.Join(runErr, stdout.Close(), stderr.Close()); err != nil {
		return nil, fmt.Errorf("%s: %w (logs: %s)", name, err, r.Output)
	}
	return os.ReadFile(filepath.Join(r.Output, name))
}

type listedPackage struct {
	Dir          string
	ImportPath   string
	TestGoFiles  []string
	XTestGoFiles []string
}

func (r *runner) list(ctx context.Context, name, tags string) (map[string]listedPackage, error) {
	data, err := r.logged(ctx, name, "go", "list", "-json", "-tags", tags,
		"./internal/pcv3operation/...", "./internal/cli")
	if err != nil {
		return nil, err
	}
	packages := make(map[string]listedPackage)
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var pkg listedPackage
		if err := decoder.Decode(&pkg); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("decode %s: %w", name, err)
		}
		if pkg.ImportPath == "" || pkg.Dir == "" {
			return nil, fmt.Errorf("incomplete package in %s", name)
		}
		packages[pkg.ImportPath] = pkg
	}
	if len(packages) == 0 {
		return nil, fmt.Errorf("no packages in %s", name)
	}
	return packages, nil
}

func (r *runner) discover(ctx context.Context) (discovery, error) {
	var discovered discovery
	baseline, err := r.list(ctx, "list-default.json", "migrated_fynedo")
	if err != nil {
		return discovered, err
	}
	tagged, err := r.list(ctx, "list-production.json", "migrated_fynedo,pcv3_production_kdf")
	if err != nil {
		return discovered, err
	}
	data, err := r.logged(ctx, "discovery.jsonl", "go", "test", "-json", "-count=1", "-p", "1",
		"-parallel", "1", "-tags", "migrated_fynedo,pcv3_production_kdf", "-list", "^(Test|Fuzz|Example)",
		"./internal/pcv3operation/...", "./internal/cli")
	if err != nil {
		return discovered, err
	}
	compiled := make(map[testID]bool)
	finished := make(map[string]bool)
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var event testEvent
		if err := decoder.Decode(&event); err != nil {
			if err == io.EOF {
				break
			}
			return discovered, fmt.Errorf("decode compiled discovery: %w", err)
		}
		if _, ok := tagged[event.Package]; !ok {
			return discovered, fmt.Errorf("compiled discovery has unknown package %q", event.Package)
		}
		switch event.Action {
		case "start":
		case "pass", "skip":
			finished[event.Package] = true
		case "output":
			for _, name := range strings.Split(strings.TrimSpace(event.Output), "\n") {
				if token.IsIdentifier(name) && (strings.HasPrefix(name, "Test") || strings.HasPrefix(name, "Fuzz") || strings.HasPrefix(name, "Example")) {
					compiled[testID{event.Package, name}] = true
				}
			}
		default:
			return discovered, fmt.Errorf("unexpected compiled discovery action %q", event.Action)
		}
	}
	for path, pkg := range tagged {
		if !finished[path] {
			return discovered, fmt.Errorf("compiled discovery did not finish package %s", path)
		}
		discovered.Packages = append(discovered.Packages, path)
		ordinaryFiles := make(map[string]bool)
		ordinary := baseline[path]
		for _, name := range append(ordinary.TestGoFiles, ordinary.XTestGoFiles...) {
			ordinaryFiles[name] = true
		}
		for _, name := range append(pkg.TestGoFiles, pkg.XTestGoFiles...) {
			if ordinaryFiles[name] {
				continue
			}
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(pkg.Dir, name), nil, 0)
			if err != nil {
				return discovered, fmt.Errorf("parse production-only test file %s: %w", name, err)
			}
			for _, declaration := range file.Decls {
				if function, ok := declaration.(*ast.FuncDecl); ok && function.Recv == nil {
					id := testID{path, function.Name.Name}
					if compiled[id] {
						discovered.Production = append(discovered.Production, id)
					}
				}
			}
		}
	}
	for parent := range compiled {
		discovered.Parents = append(discovered.Parents, parent)
	}
	if len(discovered.Production) == 0 {
		return discovered, errors.New("no compiled production-tag test parents discovered")
	}
	sort.Strings(discovered.Packages)
	for _, parents := range [][]testID{discovered.Parents, discovered.Production} {
		sort.Slice(parents, func(i, j int) bool {
			if parents[i].Package != parents[j].Package {
				return parents[i].Package < parents[j].Package
			}
			return parents[i].Test < parents[j].Test
		})
	}
	return discovered, nil
}

type testID struct {
	Package string `json:"package"`
	Test    string `json:"test"`
}

type discovery struct {
	Packages   []string `json:"packages"`
	Parents    []testID `json:"parents"`
	Production []testID `json:"production"`
}

type testEvent struct {
	Action  string
	Package string
	Test    string
	Output  string
}

type executionState struct {
	Started  bool
	Finished bool
}

func verifyExecution(input io.Reader, discovered discovery, allowLargeSkip bool) error {
	packages := make(map[string]executionState, len(discovered.Packages))
	parents := make(map[testID]bool, len(discovered.Parents))
	production := make(map[testID]bool, len(discovered.Production))
	tests := make(map[testID]executionState)
	for _, pkg := range discovered.Packages {
		packages[pkg] = executionState{}
	}
	for _, parent := range discovered.Parents {
		parents[parent] = true
	}
	for _, parent := range discovered.Production {
		production[parent] = true
	}
	decoder := json.NewDecoder(input)
	for {
		var event testEvent
		if err := decoder.Decode(&event); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("decode execution JSON: %w", err)
		}
		pkg, known := packages[event.Package]
		if !known {
			return fmt.Errorf("event for undiscovered package %q", event.Package)
		}
		if event.Action == "fail" || event.Action == "build-fail" {
			return fmt.Errorf("%s: %s/%s", event.Action, event.Package, event.Test)
		}
		if event.Action == "output" {
			continue
		}
		if event.Test == "" {
			switch event.Action {
			case "start":
				if pkg.Started {
					return fmt.Errorf("duplicate package start: %s", event.Package)
				}
				pkg.Started = true
			case "pass":
				if !pkg.Started || pkg.Finished {
					return fmt.Errorf("unexpected package pass: %s", event.Package)
				}
				pkg.Finished = true
			default:
				return fmt.Errorf("unexpected package action %q: %s", event.Action, event.Package)
			}
			packages[event.Package] = pkg
			continue
		}
		id := testID{event.Package, event.Test}
		parent := testID{event.Package, strings.SplitN(event.Test, "/", 2)[0]}
		if !parents[parent] || !pkg.Started || pkg.Finished {
			return fmt.Errorf("test outside compiled package parents: %s/%s", id.Package, id.Test)
		}
		state := tests[id]
		switch event.Action {
		case "run":
			if state.Started {
				return fmt.Errorf("duplicate test run: %s/%s", id.Package, id.Test)
			}
			state.Started = true
		case "pass", "skip":
			if !state.Started || state.Finished {
				return fmt.Errorf("test terminal event without unfinished run: %s/%s", id.Package, id.Test)
			}
			if event.Action == "skip" && (!allowLargeSkip || production[parent] ||
				id.Package != "Picocrypt-NG/internal/pcv3operation/internal/pcv3" ||
				id.Test != "TestRecoveryActualBytesBeyond64GiB") {
				return fmt.Errorf("unexpected test skip: %s/%s", id.Package, id.Test)
			}
			state.Finished = true
		case "pause", "cont":
			if !state.Started || state.Finished {
				return fmt.Errorf("test scheduling event outside run: %s/%s", id.Package, id.Test)
			}
		default:
			return fmt.Errorf("unexpected test action %q: %s/%s", event.Action, id.Package, id.Test)
		}
		tests[id] = state
	}
	for _, pkg := range discovered.Packages {
		if !packages[pkg].Finished {
			return fmt.Errorf("package did not finish successfully: %s", pkg)
		}
	}
	for _, parent := range discovered.Parents {
		if !tests[parent].Finished {
			return fmt.Errorf("compiled parent did not run and finish: %s/%s", parent.Package, parent.Test)
		}
	}
	for id, state := range tests {
		if !state.Finished {
			return fmt.Errorf("started test did not finish: %s/%s", id.Package, id.Test)
		}
	}
	return nil
}

func runMain() error {
	if err := validateEnvironment(os.Args[1:]); err != nil {
		return err
	}
	output := os.Getenv("PICOCRYPT_PRODUCTION_KDF_REPORT_DIR")
	var err error
	if output == "" {
		output, err = os.MkdirTemp(os.Getenv("RUNNER_TEMP"), "picocrypt-ng-production-kdf-")
	} else {
		output, err = filepath.Abs(output)
		if err == nil {
			var parent *os.Root
			parent, err = os.OpenRoot(filepath.Dir(output))
			if err == nil {
				err = errors.Join(parent.Mkdir(filepath.Base(output), 0o700), parent.Close())
			}
		}
	}
	if err != nil {
		return fmt.Errorf("create fresh evidence directory: %w", err)
	}
	fmt.Println("Production-KDF evidence:", output)
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	r := runner{Dir: dir, Output: output}
	report := laneReport{
		Status: "incomplete", StartedAt: time.Now().UTC(), MemoryBefore: memorySnapshot(),
		LimitsProvisional: true, PackageTimeout: packageTimeout, LaneTimeout: laneTimeout.String(),
	}
	if err := r.save(&report); err != nil {
		return err
	}
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(parent, laneTimeout)
	defer cancel()
	if err := r.identity(ctx, &report); err != nil {
		report.Status, report.Error = "failed", err.Error()
		return errors.Join(err, r.save(&report))
	}
	return r.run(ctx, &report)
}

func (r *runner) identity(ctx context.Context, report *laneReport) error {
	data, err := r.logged(ctx, "go-version.txt", "go", "version")
	if err != nil {
		return err
	}
	report.GoVersion = strings.TrimSpace(string(data))
	data, err = r.logged(ctx, "go-env.json", "go", "env", "-json", "GOOS", "GOARCH", "CGO_ENABLED", "GOFLAGS")
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &report.GoEnvironment); err != nil {
		return err
	}
	if report.GoEnvironment["GOFLAGS"] != "" {
		return errors.New("effective GOFLAGS must be empty, including saved go env configuration")
	}
	if report.GoEnvironment["GOOS"] != runtime.GOOS || report.GoEnvironment["GOARCH"] != runtime.GOARCH || report.GoEnvironment["CGO_ENABLED"] != "1" {
		return errors.New("production-KDF lane requires native GOOS/GOARCH and CGO_ENABLED=1")
	}
	for _, name := range []string{"GOMEMLIMIT", "GOMAXPROCS", "PICOCRYPT_RUN_CLI_INTEGRATION", "PICOCRYPT_RUN_RECOVERY_LARGE"} {
		report.GoEnvironment[name] = os.Getenv(name)
	}
	if report.GoEnvironment["PICOCRYPT_RUN_CLI_INTEGRATION"] != "1" {
		return errors.New("production-KDF lane requires PICOCRYPT_RUN_CLI_INTEGRATION=1")
	}
	data, err = r.logged(ctx, "source-sha.txt", "git", "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	report.SourceSHA = strings.TrimSpace(string(data))
	data, err = r.logged(ctx, "source-status.txt", "git", "status", "--porcelain", "--untracked-files=normal")
	report.Dirty = len(bytes.TrimSpace(data)) != 0
	return err
}

func main() {
	if err := runMain(); err != nil {
		fmt.Fprintln(os.Stderr, "Production-KDF lane failed:", err)
		os.Exit(1)
	}
}
