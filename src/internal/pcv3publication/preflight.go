package pcv3publication

import (
	"crypto/rand"
	"errors"
	"os"
)

// CheckCapability exercises the actual source-to-destination no-replace path
// before credential work. An unsafe public namespace cannot support safe probe
// cleanup and is refused before creating a public probe.
func (stage *Stage) CheckCapability() error {
	if stage == nil || stage.sourceRoot == nil || stage.sourceParent == nil || stage.root == nil || stage.parent == nil {
		return errors.ErrUnsupported
	}
	if !safeCapabilityParent(stage.parent) {
		return errors.ErrUnsupported
	}
	return checkCapabilityBetween(stage.sourceRoot, stage.sourceParent, stage.root, stage.parent, nativeOperations())
}

func checkCapability(root *os.Root, parent *os.File, operations platformOperations) error {
	return checkCapabilityBetween(root, parent, root, parent, operations)
}

func checkCapabilityBetween(sourceRoot *os.Root, sourceParent *os.File, targetRoot *os.Root, targetParent *os.File, operations platformOperations) (result error) {
	if operations.atomicPublish == nil {
		return errors.ErrUnsupported
	}
	type probe struct {
		root   *os.Root
		parent *os.File
		name   string
		info   os.FileInfo
		file   *os.File
	}
	probes := make([]*probe, 0, 2)
	defer func() {
		for _, p := range probes {
			info, err := p.root.Lstat(p.name)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			var owner *os.File
			if err == nil {
				for _, candidate := range probes {
					if os.SameFile(info, candidate.info) {
						owner = candidate.file
						break
					}
				}
			}
			if owner == nil || removeOwnedFile(p.root, p.name, owner, (*os.Root).Remove) != nil {
				result = errors.Join(result, ErrCleanupIncomplete)
			}
		}
		for _, p := range probes {
			if p.file != nil {
				if p.file.Close() != nil {
					result = errors.Join(result, ErrCleanupIncomplete)
				}
			}
		}
	}()
	for _, location := range []struct {
		root   *os.Root
		parent *os.File
	}{{sourceRoot, sourceParent}, {targetRoot, targetParent}} {
		name := stageNamePrefix + "probe-" + rand.Text()
		file, err := createPrivateStage(location.root, location.parent, name)
		if err != nil {
			return err
		}
		info, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return errors.Join(err, ErrCleanupIncomplete)
		}
		probes = append(probes, &probe{location.root, location.parent, name, info, file})
	}
	source, target := probes[0], probes[1]
	err := operations.atomicPublish(sourceParent, targetParent, source.file, source.name, target.name, PolicyNoReplace)
	if !errors.Is(err, os.ErrExist) || probeIdentity(sourceRoot, source.name, source.info) != identityExpected || probeIdentity(targetRoot, target.name, target.info) != identityExpected {
		return errors.Join(errors.ErrUnsupported, err)
	}
	if err := removeOwnedFile(targetRoot, target.name, target.file, (*os.Root).Remove); err != nil {
		return err
	}
	if err := target.file.Close(); err != nil {
		target.file = nil
		return err
	}
	target.file = nil
	if err := operations.atomicPublish(sourceParent, targetParent, source.file, source.name, target.name, PolicyNoReplace); err != nil {
		return errors.Join(errors.ErrUnsupported, err)
	}
	if probeIdentity(sourceRoot, source.name, source.info) != identityMissing || probeIdentity(targetRoot, target.name, source.info) != identityExpected {
		return errors.ErrUnsupported
	}
	return nil
}
