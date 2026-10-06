package pcv3publication

import (
	"crypto/rand"
	"errors"
	"os"
)

// CheckCapability exercises atomic no-replace publication on this stage's pinned
// directory before a writer spends credentials or KDF resources. OS/API versions
// alone do not establish filesystem capability. It never touches the real target.
func (stage *Stage) CheckCapability() error {
	if stage == nil || stage.root == nil || stage.parent == nil {
		return errors.ErrUnsupported
	}
	return checkCapability(stage.root, stage.parent, nativeOperations())
}

func checkCapability(root *os.Root, parent *os.File, operations platformOperations) (result error) {
	if operations.atomicPublish == nil {
		return errors.ErrUnsupported
	}
	type probe struct {
		name string
		info os.FileInfo
	}
	probes := make([]probe, 0, 2)
	defer func() {
		for _, p := range probes {
			info, err := root.Lstat(p.name)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			owned := false
			if err == nil {
				for _, candidate := range probes {
					if os.SameFile(info, candidate.info) {
						owned = true
						break
					}
				}
			}
			if !owned {
				result = errors.Join(result, ErrCleanupIncomplete)
				continue
			}
			if err := root.Remove(p.name); err != nil {
				result = errors.Join(result, ErrCleanupIncomplete)
			}
		}
	}()
	for range 2 {
		name := stageNamePrefix + "probe-" + rand.Text()
		file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			return err
		}
		info, statErr := file.Stat()
		closeErr := file.Close()
		if statErr != nil {
			return errors.Join(statErr, closeErr, ErrCleanupIncomplete)
		}
		probes = append(probes, probe{name, info})
		if closeErr != nil {
			return closeErr
		}
	}
	source, target := probes[0], probes[1]
	// Collision refusal must leave both independently owned inodes unchanged.
	err := operations.atomicPublish(parent, source.name, target.name, PolicyNoReplace)
	if !errors.Is(err, os.ErrExist) || probeIdentity(root, source.name, source.info) != identityExpected || probeIdentity(root, target.name, target.info) != identityExpected {
		return errors.Join(errors.ErrUnsupported, err)
	}
	if err := root.Remove(target.name); err != nil {
		return err
	}
	if err := operations.atomicPublish(parent, source.name, target.name, PolicyNoReplace); err != nil {
		return errors.Join(errors.ErrUnsupported, err)
	}
	if probeIdentity(root, source.name, source.info) != identityMissing || probeIdentity(root, target.name, source.info) != identityExpected {
		return errors.ErrUnsupported
	}
	return nil
}
