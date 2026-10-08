package fileops

import (
	"errors"
	"os"
	"path/filepath"
)

// PreparedZIPUnpack holds admitted metadata and extraction workspace across an
// archive rename. Close retires its charges, but never closes the borrowed file.
// Copies share one single-use state. Like Unpack, it is used synchronously.
type PreparedZIPUnpack struct{ state *preparedZIPUnpackState }

type preparedZIPUnpackState struct {
	reader    *ZIPReader
	source    *preparedZIPSource
	info      os.FileInfo
	directory string
	working   uint64
	used      bool
}

type preparedZIPSource struct{ file *os.File }

func (source *preparedZIPSource) ReadAt(data []byte, offset int64) (int, error) {
	if source.file == nil {
		return 0, os.ErrClosed
	}
	return source.file.ReadAt(data, offset)
}

// PrepareZIPUnpack runs the same bounded parser and workspace admission as
// Unpack without creating output. The parsed metadata is retained, so later
// changes to central-directory bytes cannot expand the admitted extraction plan.
func PrepareZIPUnpack(file *os.File, directory string, opts ZIPReadOptions) (*PreparedZIPUnpack, error) {
	if file == nil {
		return nil, os.ErrInvalid
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	source := &preparedZIPSource{file: file}
	reader, err := OpenZIPReader(source, info.Size(), opts)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = reader.Close()
		}
	}()
	opts.Budget = reader.Budget()
	if err := ValidateZIPPayloadRanges(reader.File, opts); err != nil {
		return nil, err
	}
	working, err := zipUnpackWorkingBytes(reader.Reader, len(absolute))
	if err != nil {
		return nil, err
	}
	if err := opts.Budget.Reserve(working); err != nil {
		return nil, err
	}
	keep = true
	return &PreparedZIPUnpack{state: &preparedZIPUnpackState{reader: reader, source: source, info: info, directory: absolute, working: working}}, nil
}

func (prepared *PreparedZIPUnpack) use(file *os.File, directory string, budget *ZIPResourceBudget) (*ZIPReader, error) {
	if prepared == nil || prepared.state == nil || prepared.state.reader == nil || prepared.state.used || file == nil {
		return nil, os.ErrInvalid
	}
	state := prepared.state
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if absolute != state.directory || budget != state.reader.Budget() || !os.SameFile(state.info, info) || info.Size() != state.info.Size() {
		return nil, errors.New("prepared ZIP source, destination or budget changed")
	}
	state.used = true
	state.source.file = file
	return state.reader, nil
}

func (prepared *PreparedZIPUnpack) Close() error {
	if prepared == nil || prepared.state == nil || prepared.state.reader == nil {
		return nil
	}
	state := prepared.state
	state.reader.Budget().Release(state.working)
	err := state.reader.Close()
	state.reader = nil
	state.source.file = nil
	return err
}
