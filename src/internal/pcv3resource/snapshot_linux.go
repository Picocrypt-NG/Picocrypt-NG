//go:build linux && !android

package pcv3resource

import (
	"context"
	"io"
	"io/fs"
	"math"
	"os"
	"path"
	"strconv"
	"strings"
)

const (
	maxLinuxFactBytes  = 64 << 10
	maxMountInfoBytes  = 1 << 20
	maxCgroupPathDepth = 64
	maxLinuxPathBytes  = 4096
	// Linux cgroup v1 represents an unlimited memory limit with a page-aligned
	// value close to MaxInt64. Values this large cannot constrain a process on
	// a supported address space and are omitted rather than treated as zero.
	v1UnlimitedLimit = uint64(1) << 60
)

type linuxSnapshotProvider struct {
	procRootPath       string
	filesystemRootPath string
}

type linuxProcessMemory struct {
	virtual  uint64
	resident uint64
}

type linuxAddressSpaceLimit struct {
	finite bool
	bytes  uint64
}

type linuxCgroupKind uint8

const (
	linuxCgroupNone linuxCgroupKind = iota
	linuxCgroupV1
	linuxCgroupV2
)

type linuxCgroupSelection struct {
	kind       linuxCgroupKind
	membership string
	mountRoot  string
	mountPoint string
}

type linuxMount struct {
	kind       linuxCgroupKind
	root       string
	mountPoint string
}

func newPlatformSnapshotProvider() snapshotProvider {
	return linuxSnapshotProvider{
		procRootPath:       "/proc",
		filesystemRootPath: "/",
	}
}

func (provider linuxSnapshotProvider) Snapshot(ctx context.Context) Snapshot {
	available, reserve, ok := provider.observe(ctx)
	if !ok {
		return newSnapshot(
			snapshotSourceLinux,
			snapshotStateUnconfigured,
			0,
			0,
			0,
			false,
		)
	}
	return newSnapshot(
		snapshotSourceLinux,
		snapshotStateReady,
		available,
		0,
		reserve,
		false,
	)
}

func (provider linuxSnapshotProvider) observe(ctx context.Context) (uint64, uint64, bool) {
	if ctx == nil || ctx.Err() != nil || provider.procRootPath == "" ||
		provider.filesystemRootPath == "" {
		return 0, 0, false
	}

	procRoot, err := os.OpenRoot(provider.procRootPath)
	if err != nil {
		return 0, 0, false
	}
	meminfo, ok := readLinuxFact(ctx, procRoot, "meminfo", maxLinuxFactBytes)
	if !ok {
		_ = procRoot.Close()
		return 0, 0, false
	}
	status, ok := readLinuxFact(ctx, procRoot, "self/status", maxLinuxFactBytes)
	if !ok {
		_ = procRoot.Close()
		return 0, 0, false
	}
	limits, ok := readLinuxFact(ctx, procRoot, "self/limits", maxLinuxFactBytes)
	if !ok {
		_ = procRoot.Close()
		return 0, 0, false
	}
	cgroup, ok := readLinuxFact(ctx, procRoot, "self/cgroup", maxLinuxFactBytes)
	if !ok {
		_ = procRoot.Close()
		return 0, 0, false
	}
	mountinfo, ok := readLinuxFact(ctx, procRoot, "self/mountinfo", maxMountInfoBytes)
	if !ok || procRoot.Close() != nil || ctx.Err() != nil {
		return 0, 0, false
	}

	memAvailable, _, ok := parseLinuxMeminfo(meminfo)
	if !ok {
		return 0, 0, false
	}
	process, ok := parseLinuxProcessMemory(status)
	if !ok {
		return 0, 0, false
	}
	addressLimit, ok := parseLinuxAddressSpaceLimit(limits)
	if !ok {
		return 0, 0, false
	}
	selection, ok := selectLinuxMemoryCgroup(cgroup, mountinfo)
	if !ok {
		return 0, 0, false
	}

	effective := memAvailable
	if addressLimit.finite {
		if addressLimit.bytes <= process.virtual {
			return 0, 0, false
		}
		effective = min(effective, addressLimit.bytes-process.virtual)
	}
	if selection.kind != linuxCgroupNone {
		filesystemRoot, err := os.OpenRoot(provider.filesystemRootPath)
		if err != nil {
			return 0, 0, false
		}
		cgroupHeadroom, constrained, valid := readLinuxCgroupHeadroom(
			ctx,
			filesystemRoot,
			selection,
		)
		if closeErr := filesystemRoot.Close(); closeErr != nil {
			valid = false
		}
		if !valid || ctx.Err() != nil {
			return 0, 0, false
		}
		if constrained {
			effective = min(effective, cgroupHeadroom)
		}
	}
	if effective == 0 || process.resident == 0 {
		return 0, 0, false
	}
	return effective, process.resident, true
}

func readLinuxFact(ctx context.Context, root *os.Root, name string, maximum int64) ([]byte, bool) {
	if ctx == nil || ctx.Err() != nil || root == nil || maximum <= 0 ||
		!fs.ValidPath(name) {
		return nil, false
	}
	info, err := root.Lstat(name)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Size() < 0 || info.Size() > maximum {
		return nil, false
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, false
	}
	opened, statErr := file.Stat()
	if statErr != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, false
	}
	contents, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(contents)) > maximum ||
		len(contents) == 0 || strings.IndexByte(string(contents), 0) >= 0 ||
		ctx.Err() != nil {
		return nil, false
	}
	return contents, true
}

func parseLinuxMeminfo(contents []byte) (uint64, uint64, bool) {
	values, ok := parseUniqueLinuxKBFields(contents, "MemAvailable", "MemTotal")
	if !ok {
		return 0, 0, false
	}
	available := values["MemAvailable"]
	total := values["MemTotal"]
	if available == 0 || total == 0 || available > total {
		return 0, 0, false
	}
	return available, total, true
}

func parseLinuxProcessMemory(contents []byte) (linuxProcessMemory, bool) {
	values, ok := parseUniqueLinuxKBFields(contents, "VmRSS", "VmSize")
	if !ok {
		return linuxProcessMemory{}, false
	}
	result := linuxProcessMemory{
		virtual:  values["VmSize"],
		resident: values["VmRSS"],
	}
	if result.virtual == 0 || result.resident == 0 || result.resident > result.virtual {
		return linuxProcessMemory{}, false
	}
	return result, true
}

func parseUniqueLinuxKBFields(contents []byte, names ...string) (map[string]uint64, bool) {
	wanted := make(map[string]struct{}, len(names))
	for _, name := range names {
		wanted[name] = struct{}{}
	}
	values := make(map[string]uint64, len(names))
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := strings.TrimSuffix(fields[0], ":")
		if _, relevant := wanted[name]; !relevant {
			continue
		}
		if fields[0] != name+":" || len(fields) != 3 || fields[2] != "kB" {
			return nil, false
		}
		if _, duplicate := values[name]; duplicate {
			return nil, false
		}
		kilobytes, ok := parseLinuxDecimal(fields[1])
		if !ok || kilobytes > math.MaxUint64/1024 {
			return nil, false
		}
		values[name] = kilobytes * 1024
	}
	if len(values) != len(wanted) {
		return nil, false
	}
	return values, true
}

func parseLinuxAddressSpaceLimit(contents []byte) (linuxAddressSpaceLimit, bool) {
	var result linuxAddressSpaceLimit
	found := false
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "Max" || fields[1] != "address" || fields[2] != "space" {
			continue
		}
		if found || len(fields) != 6 || fields[5] != "bytes" {
			return linuxAddressSpaceLimit{}, false
		}
		found = true
		softUnlimited := fields[3] == "unlimited"
		hardUnlimited := fields[4] == "unlimited"
		if softUnlimited {
			if !hardUnlimited {
				return linuxAddressSpaceLimit{}, false
			}
			continue
		}
		soft, ok := parseLinuxDecimal(fields[3])
		if !ok || soft == 0 {
			return linuxAddressSpaceLimit{}, false
		}
		if !hardUnlimited {
			hard, ok := parseLinuxDecimal(fields[4])
			if !ok || hard == 0 || soft > hard {
				return linuxAddressSpaceLimit{}, false
			}
		}
		result = linuxAddressSpaceLimit{finite: true, bytes: soft}
	}
	return result, found
}

func selectLinuxMemoryCgroup(cgroup, mountinfo []byte) (linuxCgroupSelection, bool) {
	v1Path, v2Path, anyMembership, ok := parseLinuxCgroupMemberships(cgroup)
	if !ok || !anyMembership {
		return linuxCgroupSelection{}, false
	}
	mounts, ok := parseLinuxCgroupMounts(mountinfo)
	if !ok {
		return linuxCgroupSelection{}, false
	}
	kind := linuxCgroupV2
	membership := v2Path
	if v1Path != "" {
		kind = linuxCgroupV1
		membership = v1Path
	}
	if membership == "" {
		return linuxCgroupSelection{kind: linuxCgroupNone}, true
	}
	var selected *linuxMount
	for index := range mounts {
		mount := &mounts[index]
		if mount.kind != kind || !linuxPathContains(mount.root, membership) {
			continue
		}
		if selected != nil {
			return linuxCgroupSelection{}, false
		}
		selected = mount
	}
	if selected == nil {
		return linuxCgroupSelection{}, false
	}
	return linuxCgroupSelection{
		kind:       kind,
		membership: membership,
		mountRoot:  selected.root,
		mountPoint: selected.mountPoint,
	}, true
}

func parseLinuxCgroupMemberships(contents []byte) (string, string, bool, bool) {
	var v1Path, v2Path string
	any := false
	for _, line := range strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n") {
		if line == "" {
			return "", "", false, false
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			return "", "", false, false
		}
		if _, ok := parseLinuxDecimal(parts[0]); !ok {
			return "", "", false, false
		}
		membership, ok := cleanLinuxAbsolutePath(parts[2])
		if !ok {
			return "", "", false, false
		}
		any = true
		if parts[1] == "" {
			if parts[0] != "0" || v2Path != "" {
				return "", "", false, false
			}
			v2Path = membership
			continue
		}
		controllers := strings.Split(parts[1], ",")
		seen := make(map[string]struct{}, len(controllers))
		for _, controller := range controllers {
			if controller == "" {
				return "", "", false, false
			}
			if _, duplicate := seen[controller]; duplicate {
				return "", "", false, false
			}
			seen[controller] = struct{}{}
		}
		if _, memory := seen["memory"]; memory {
			if v1Path != "" {
				return "", "", false, false
			}
			v1Path = membership
		}
	}
	return v1Path, v2Path, any, true
}

func parseLinuxCgroupMounts(contents []byte) ([]linuxMount, bool) {
	var mounts []linuxMount
	for _, line := range strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n") {
		if line == "" {
			return nil, false
		}
		fields := strings.Fields(line)
		separator := -1
		for index, field := range fields {
			if field == "-" {
				if separator != -1 {
					return nil, false
				}
				separator = index
			}
		}
		if len(fields) < 10 || separator < 6 || separator+3 >= len(fields) {
			return nil, false
		}
		filesystem := fields[separator+1]
		kind := linuxCgroupNone
		switch filesystem {
		case "cgroup2":
			kind = linuxCgroupV2
		case "cgroup":
			if linuxCommaListContains(fields[separator+3], "memory") {
				kind = linuxCgroupV1
			}
		}
		if kind == linuxCgroupNone {
			continue
		}
		mountRoot, ok := decodeLinuxMountPath(fields[3])
		if !ok {
			return nil, false
		}
		mountPoint, ok := decodeLinuxMountPath(fields[4])
		if !ok {
			return nil, false
		}
		mounts = append(mounts, linuxMount{
			kind:       kind,
			root:       mountRoot,
			mountPoint: mountPoint,
		})
	}
	return mounts, true
}

func readLinuxCgroupHeadroom(
	ctx context.Context,
	root *os.Root,
	selection linuxCgroupSelection,
) (uint64, bool, bool) {
	levels, ok := linuxCgroupLevels(selection)
	if !ok {
		return 0, false, false
	}
	var minimum uint64
	constrained := false
	for _, level := range levels {
		if ctx == nil || ctx.Err() != nil {
			return 0, false, false
		}
		limitName := "memory.max"
		usageName := "memory.current"
		if selection.kind == linuxCgroupV1 {
			limitName = "memory.limit_in_bytes"
			usageName = "memory.usage_in_bytes"
		}
		limitBytes, ok := readLinuxFact(ctx, root, path.Join(level, limitName), maxLinuxFactBytes)
		if !ok {
			return 0, false, false
		}
		limit, finite, ok := parseLinuxCgroupLimit(limitBytes, selection.kind)
		if !ok {
			return 0, false, false
		}
		if !finite {
			continue
		}
		usageBytes, ok := readLinuxFact(ctx, root, path.Join(level, usageName), maxLinuxFactBytes)
		if !ok {
			return 0, false, false
		}
		usage, ok := parseLinuxCgroupValue(usageBytes)
		if !ok || usage > limit {
			return 0, false, false
		}
		headroom := limit - usage
		if !constrained || headroom < minimum {
			minimum = headroom
		}
		constrained = true
	}
	if constrained && minimum == 0 {
		return 0, false, false
	}
	return minimum, constrained, true
}

func linuxCgroupLevels(selection linuxCgroupSelection) ([]string, bool) {
	if selection.kind != linuxCgroupV1 && selection.kind != linuxCgroupV2 {
		return nil, false
	}
	mountPoint, ok := linuxRootRelativePath(selection.mountPoint)
	if !ok || !linuxPathContains(selection.mountRoot, selection.membership) {
		return nil, false
	}
	relative := strings.TrimPrefix(selection.membership, selection.mountRoot)
	relative = strings.TrimPrefix(relative, "/")
	levels := []string{mountPoint}
	if relative == "" {
		return levels, true
	}
	components := strings.Split(relative, "/")
	if len(components) > maxCgroupPathDepth {
		return nil, false
	}
	current := mountPoint
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			return nil, false
		}
		current = path.Join(current, component)
		if !fs.ValidPath(current) {
			return nil, false
		}
		levels = append(levels, current)
	}
	return levels, true
}

func parseLinuxCgroupLimit(contents []byte, kind linuxCgroupKind) (uint64, bool, bool) {
	token, ok := singleLinuxToken(contents)
	if !ok {
		return 0, false, false
	}
	if kind == linuxCgroupV2 && token == "max" {
		return 0, false, true
	}
	limit, ok := parseLinuxDecimal(token)
	if !ok || limit == 0 {
		return 0, false, false
	}
	if kind == linuxCgroupV1 && limit >= v1UnlimitedLimit {
		return 0, false, true
	}
	return limit, true, true
}

func parseLinuxCgroupValue(contents []byte) (uint64, bool) {
	token, ok := singleLinuxToken(contents)
	if !ok {
		return 0, false
	}
	return parseLinuxDecimal(token)
}

func singleLinuxToken(contents []byte) (string, bool) {
	text := string(contents)
	if strings.HasSuffix(text, "\n") {
		text = strings.TrimSuffix(text, "\n")
	}
	if text == "" || strings.ContainsAny(text, " \t\r\n") {
		return "", false
	}
	return text, true
}

func parseLinuxDecimal(value string) (uint64, bool) {
	if value == "" {
		return 0, false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, false
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	return parsed, err == nil
}

func linuxCommaListContains(list, wanted string) bool {
	for _, value := range strings.Split(list, ",") {
		if value == wanted {
			return true
		}
	}
	return false
}

func decodeLinuxMountPath(encoded string) (string, bool) {
	var decoded strings.Builder
	for index := 0; index < len(encoded); {
		if encoded[index] != '\\' {
			decoded.WriteByte(encoded[index])
			index++
			continue
		}
		if index+4 > len(encoded) {
			return "", false
		}
		escape := encoded[index : index+4]
		switch escape {
		case `\040`:
			decoded.WriteByte(' ')
		case `\011`:
			decoded.WriteByte('\t')
		case `\012`:
			decoded.WriteByte('\n')
		case `\134`:
			decoded.WriteByte('\\')
		default:
			return "", false
		}
		index += 4
	}
	return cleanLinuxAbsolutePath(decoded.String())
}

func cleanLinuxAbsolutePath(value string) (string, bool) {
	if value == "" || len(value) > maxLinuxPathBytes || value[0] != '/' ||
		strings.ContainsAny(value, "\x00\r\n\\") ||
		path.Clean(value) != value {
		return "", false
	}
	if _, ok := linuxRootRelativePath(value); !ok {
		return "", false
	}
	return value, true
}

func linuxRootRelativePath(absolute string) (string, bool) {
	if absolute == "/" {
		return ".", true
	}
	if absolute == "" || absolute[0] != '/' {
		return "", false
	}
	relative := strings.TrimPrefix(absolute, "/")
	if !fs.ValidPath(relative) {
		return "", false
	}
	return relative, true
}

func linuxPathContains(parent, child string) bool {
	return parent == "/" || child == parent || strings.HasPrefix(child, parent+"/")
}
